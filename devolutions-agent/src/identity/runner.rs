//! The per-authority runner: renewal, confirmation, check-in and agent channel of one stored identity.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use agent_channel_client::{ChannelClient, HelloFields, Target};
use agent_identity::client::{self, Client, ClientError, RequestSigner, TerminalCode};
use agent_identity::schedule::{self, ChannelUrl};
use agent_identity::state::{KEY_LOST, KeyRecord, KeySlots, Store, StoredIdentity};
use agent_identity::{csr, metadata};
use anyhow::Context as _;
use device_key::DeviceKey;
use devolutions_gateway_task::ShutdownSignal;
use rand::Rng as _;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use super::RetryState;
use super::channel::{LinkId, Notice, Streams, Want};
use super::config::IdentityDebugConf;

const CHECK_IN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const CHANNEL_FAILURE_CHECK_IN_AFTER: Duration = Duration::from_secs(60 * 60);
/// Bounds every wait, so that a wall-clock change delays a scheduled action by at most this long.
const MAX_WAIT: Duration = Duration::from_secs(60);

/// The state and services every runner shares with pending enrollment.
pub(super) struct Shared {
    pub(super) store: Store,
    pub(super) client: Client,
    pub(super) channels: ChannelClient,
    pub(super) settings: IdentityDebugConf,
}

/// One runner per stored, non-rejected identity, keyed by authority.
pub(super) struct Runners {
    shared: Arc<Shared>,
    shutdown: ShutdownSignal,
    tasks: HashMap<Uuid, tokio::task::JoinHandle<()>>,
}

impl Runners {
    pub(super) fn new(shared: Arc<Shared>, shutdown: ShutdownSignal) -> Self {
        Self {
            shared,
            shutdown,
            tasks: HashMap::new(),
        }
    }

    /// Starts the runner of a stored identity and stops the runner of the identity it replaces.
    pub(super) fn start(&mut self, identity: &StoredIdentity) {
        if let Some(replaced) = self.tasks.remove(&identity.authority_id) {
            replaced.abort();
        }
        if identity.rejected.is_some() {
            return;
        }
        let runner = Runner::new(Arc::clone(&self.shared), identity);
        let task = tokio::spawn(runner.run(self.shutdown.clone()));
        self.tasks.insert(identity.authority_id, task);
    }
}

impl Drop for Runners {
    fn drop(&mut self) {
        for task in self.tasks.values() {
            task.abort();
        }
    }
}

struct Runner {
    shared: Arc<Shared>,
    authority_id: Uuid,
    identity_id: Uuid,
    /// Backoff of the renew and confirm requests of one renewal.
    renewal_retry: RetryState,
    check_in_retry: RetryState,
    /// Backoff after a local failure, such as a busy state lock.
    local_retry: RetryState,
    renewal_requested: bool,
    /// A terminal outcome the authority returned, recorded before any other action.
    terminal: Option<&'static str>,
    /// Whether pending-key recovery signs with the current key after the expired pending key drew `identity_unknown`.
    recovery_signs_with_current: bool,
    /// When this run stored or loaded each certificate, which anchors its renewal schedule.
    load_times: LoadTimes,
    /// The renewal jitter sample of the current key, drawn once for each key.
    renewal_jitter: Option<(String, f64)>,
    /// `None` while a check-in waits for a renewal to be confirmed.
    next_check_in: Option<Instant>,
    check_in_after_confirm: bool,
    channel_url: Option<Url>,
    warned_malformed_config: Option<Value>,
    streams: Streams,
    /// What the streams reported and the runner hasn't handled yet.
    notices: VecDeque<Notice>,
    /// Whether a `confirm` may have succeeded without this run knowing it: one was sent and no `204` answered it
    /// since, or the run started with a pending slot.
    confirm_unknown: bool,
    /// Whether the agent channel waits for the next `confirm`, because its certificate expired.
    channel_after_confirm: bool,
    /// The stored `config.revision`, which each `Hello` reports.
    config_revision: Arc<AtomicU64>,
}

impl Runner {
    fn new(shared: Arc<Shared>, identity: &StoredIdentity) -> Self {
        let mut runner = Self {
            shared,
            authority_id: identity.authority_id,
            identity_id: identity.identity_id,
            renewal_retry: RetryState::default(),
            check_in_retry: RetryState::default(),
            local_retry: RetryState::default(),
            renewal_requested: false,
            terminal: None,
            recovery_signs_with_current: false,
            load_times: LoadTimes::default(),
            renewal_jitter: None,
            next_check_in: None,
            check_in_after_confirm: false,
            channel_url: None,
            warned_malformed_config: None,
            streams: Streams::spawn(),
            notices: VecDeque::new(),
            confirm_unknown: identity.keys.pending.is_some(),
            channel_after_confirm: false,
            config_revision: Arc::new(AtomicU64::new(0)),
        };
        // `crates/agent-identity/INTENT.md` ("Schedules"): without a channel URL, check in when the runner starts;
        // with one, once no stream has authenticated for 1 h, counted from the runner's start.
        let now = Instant::now();
        let loaded_at = SystemTime::now();
        for record in std::iter::once(&identity.keys.current)
            .chain(identity.keys.pending.iter())
            .chain(identity.keys.previous.iter())
            .filter(|record| record.certificate_chain.is_some())
        {
            runner.load_times.record(&record.key_name, loaded_at);
        }
        runner.channel_url = runner.usable_channel_url(identity);
        runner.next_check_in = Some(if runner.channel_url.is_some() {
            now + runner.channel_failure_check_in_after()
        } else {
            now
        });
        runner
    }

    async fn run(mut self, mut shutdown: ShutdownSignal) {
        loop {
            let step = tokio::select! {
                step = self.step() => step,
                _ = shutdown.wait() => return,
            };
            let wake = match step {
                Ok(Some(wake)) => {
                    self.local_retry.succeeded();
                    wake
                }
                Ok(None) => return,
                Err(error) => {
                    warn!(
                        authority_id = %self.authority_id,
                        error = format!("{error:#}"),
                        "Agent Identity runner failed; retrying"
                    );
                    self.local_retry.failed(&self.shared.settings, None);
                    self.local_retry.next_attempt.unwrap_or_else(Instant::now)
                }
            };
            // The streams wake the runner with a notice, which its next step handles, or a change of their status.
            tokio::select! {
                _ = tokio::time::sleep_until(wake.into()) => {}
                notice = self.streams.wait() => self.notices.extend(notice),
                _ = shutdown.wait() => return,
            }
        }
    }

    /// Takes the next action of the identity, and returns when to take the following one, or `None` to stop.
    async fn step(&mut self) -> anyhow::Result<Option<Instant>> {
        let shared = Arc::clone(&self.shared);
        let store = &shared.store;
        let Some(mut identity) = store.read_identity(self.authority_id)? else {
            return Ok(None);
        };
        if identity.identity_id != self.identity_id || identity.rejected.is_some() {
            return Ok(None);
        }
        self.handle_notices(&mut identity)?;
        if let Some(code) = self.terminal {
            self.streams.reconcile(Want::Nothing).await;
            // UNTESTED: a latched terminal outcome sends no further signed request while its record fails to persist.
            // A local write failure must not let the runner retry the operation that drew the terminal outcome.
            // When changing this, keep the latch checked before any request and set before any persistence.
            // `CONTRACT.agent-identity.md` §5.4: a terminal outcome ends the identity when it is received, so nothing
            // else is sent while its record is retried.
            store.reject_identity(&mut identity, code)?;
            warn!(
                authority_id = %self.authority_id,
                identity_id = %self.identity_id,
                code,
                "The Agent Identity is rejected; it stops renewing and checking in"
            );
            return Ok(None);
        }
        self.load_times.retain(&identity.keys);
        let now = Instant::now();
        // `crates/agent-identity/INTENT.md` ("Stored identities"): `previous` alongside `pending` holds the expired
        // pending key of a pending-key recovery; alone, it holds the old key of a confirmed renewal.
        let recovering = identity.keys.previous.is_some() && identity.keys.pending.is_some();
        if identity.keys.previous.is_some() && !recovering {
            store.remove_previous_key(&mut identity)?;
        }
        let confirming = identity
            .keys
            .pending
            .as_ref()
            .is_some_and(|pending| pending.certificate_chain.is_some());
        self.config_revision
            .store(config_revision(&identity.config), Ordering::Relaxed);
        self.follow_channel_url(&identity, now);
        self.reconcile_channel(&identity).await?;
        if self.terminal.is_some() {
            return Ok(Some(Instant::now()));
        }
        if identity.keys.pending.is_some() {
            // UNTESTED: no check-in is sent while any pending slot exists, including after an unusable pending key
            // was replaced and after a restart.
            // A check-in signed with a current key that an unconfirmed `confirm` retired draws a terminal
            // `identity_unknown`; when changing this, keep check-in behind every pending slot.
            // `CONTRACT.agent-identity.md` §8.1: while the outcome of a `confirm` is unknown, the agent sends no other
            // signed request.
            // Any pending slot holds this barrier until a `confirm` succeeds: during pending-key recovery, and after an
            // unusable pending key was replaced, an earlier `confirm` may have retired the current key.
            if !self.renewal_retry.is_due() {
                return Ok(self.renewal_retry.next_attempt);
            }
            if confirming && !self.confirm_unknown && self.streams.opening(now) {
                // `CONTRACT.md` §8.1 step 3: once `confirm` is sent, no stream opens until its outcome is known, so a
                // stream that is opening completes first; the client's opening timeout bounds the wait, and the
                // stream's next event wakes the runner.
                return Ok(Some(now + MAX_WAIT));
            }
            if confirming {
                self.confirm(&mut identity, recovering).await?;
            } else {
                self.renew(&mut identity, recovering).await?;
            }
            return Ok(Some(Instant::now()));
        }

        let renewal_at = if self.renewal_requested {
            now
        } else {
            self.renewal_at(&identity, now)?
        };
        let renewal_wake = later(renewal_at, self.renewal_retry.next_attempt);
        if renewal_wake <= now {
            self.renew(&mut identity, false).await?;
            return Ok(Some(Instant::now()));
        }
        // UNTESTED: check-in waits while a stream is authenticated, however overdue it is.
        // When changing this, keep check-in for the time without an authenticated stream.
        // `crates/agent-identity/INTENT.md` ("Schedules"): check-in runs only while the identity has no authenticated
        // stream.
        let check_in_wake = self
            .next_check_in
            .filter(|_| !self.streams.authenticated())
            .map(|check_in_at| later(check_in_at, self.check_in_retry.next_attempt));
        if check_in_wake.is_some_and(|wake| wake <= now) {
            self.check_in(&mut identity).await?;
            return Ok(Some(Instant::now()));
        }
        let wake = check_in_wake.map_or(renewal_wake, |wake| wake.min(renewal_wake));
        Ok(Some(wake.min(now + MAX_WAIT)))
    }

    /// Sends renew for the pending key, recording a fresh one first when there is none or it is unusable.
    ///
    /// The request is signed with the current key, or during pending-key recovery with the expired pending key held
    /// in `previous`, then with the current key once that draws `identity_unknown` (`CONTRACT.agent-identity.md` §8.1).
    async fn renew(&mut self, identity: &mut StoredIdentity, recovering: bool) -> anyhow::Result<()> {
        let store = &self.shared.store;
        let new_key = match &identity.keys.pending {
            None => store.create_pending_key(identity).context("record the renewal key")?,
            Some(pending) => match self.open_usable(pending) {
                Some(key) => key,
                None => store
                    .replace_pending_key(identity)
                    .context("replace the unusable pending key")?,
            },
        };
        let signs_with_expired_pending = recovering && !self.recovery_signs_with_current;
        let signer = if signs_with_expired_pending {
            let expired = identity
                .keys
                .previous
                .clone()
                .context("pending-key recovery has no expired pending key")?;
            let Some(key) = self.open_usable(&expired) else {
                // `CONTRACT.agent-identity.md` §8.1: without a usable pending key, renew with a fresh key signed by the
                // current certificate.
                store.remove_previous_key(identity)?;
                return Ok(());
            };
            client::request_signer(Arc::from(key), certificate_chain(&expired)?)?
        } else {
            let Some(signer) = self.current_signer(identity)? else {
                return Ok(());
            };
            signer
        };
        let csr = csr::create(new_key.as_ref()).context("create renewal CSR")?;
        let metadata = self.metadata();
        let result = self
            .shared
            .client
            .renew(
                &identity.base_url,
                &signer,
                &csr,
                &new_key.public_key(),
                &metadata,
                None,
            )
            .await;
        match result {
            Ok(response) => {
                self.shared
                    .store
                    .store_pending_chain(identity, response.certificate_chain)?;
                // UNTESTED: the time renew stored the pending certificate anchors its schedule after it is promoted.
                // Only `LoadTimes` is tested, not this wiring; when changing it, record before any confirm can promote.
                if let Some(pending) = &identity.keys.pending {
                    self.load_times.record(&pending.key_name, SystemTime::now());
                }
                self.renewal_retry.succeeded();
                self.recovery_signs_with_current = false;
            }
            Err(ClientError::Terminal(TerminalCode::IdentityUnknown)) if signs_with_expired_pending => {
                // `CONTRACT.agent-identity.md` §8.1: the server holds neither certificate, so retry the same renewal
                // signed with the old current key.
                warn!(
                    authority_id = %self.authority_id,
                    "Agent Identity recovery renewal is unknown to the authority; retrying with the current key"
                );
                self.recovery_signs_with_current = true;
            }
            // `CONTRACT.agent-identity.md` §5.4 and §8.1: on renew, `certificate_expired` means beyond grace, which is
            // terminal.
            Err(ClientError::CertificateExpired) => self.reject("certificate_expired"),
            Err(ClientError::Terminal(code)) => self.reject(code.as_str()),
            Err(error) => {
                warn!(authority_id = %self.authority_id, error = %error, "Agent Identity renewal will retry");
                self.renewal_retry.failed(&self.shared.settings, error.retry_after());
            }
        }
        Ok(())
    }

    async fn confirm(&mut self, identity: &mut StoredIdentity, recovering: bool) -> anyhow::Result<()> {
        let store = &self.shared.store;
        let pending = identity.keys.pending.clone().context("identity has no pending key")?;
        let Some(key) = self.open_usable(&pending) else {
            // `crates/agent-identity/INTENT.md` ("Stored identities"): delete an unusable pending key and its slot
            // before renewing with a fresh key.
            store
                .replace_pending_key(identity)
                .context("replace the unusable pending key")?;
            return Ok(());
        };
        let signer = client::request_signer(Arc::from(key), certificate_chain(&pending)?)?;
        // UNTESTED: `confirm` is sent only after the streams are held, which drops every stream that hasn't
        // authenticated; an opening that reaches the authority after `confirm` retired its key draws the terminal
        // `identity_unknown`. When changing this, hold the streams before every `confirm`.
        // `CONTRACT.md` §8.1 step 3: from now until a `204`, the outcome of a `confirm` may be unknown, so no stream
        // opens.
        self.confirm_unknown = true;
        self.streams.reconcile(Want::Hold).await;
        let result = self.shared.client.confirm(&identity.base_url, &signer, None).await;
        match result {
            Ok(()) => {
                if recovering {
                    // `crates/agent-identity/INTENT.md` ("Stored identities"): once the next `confirm` succeeds,
                    // delete the expired pending key, then promote as usual.
                    store.remove_previous_key(identity)?;
                }
                store.promote_pending(identity)?;
                self.renewal_retry.succeeded();
                self.renewal_requested = false;
                self.confirm_unknown = false;
                self.channel_after_confirm = false;
                if std::mem::take(&mut self.check_in_after_confirm) {
                    self.next_check_in = Some(Instant::now());
                }
                info!(
                    authority_id = %self.authority_id,
                    identity_id = %self.identity_id,
                    "Agent Identity certificate renewed"
                );
                // `CONTRACT.md` §8.1 step 4: a stream with the new key opens at once, and the old stream closes once
                // it authenticates.
                self.reconcile_channel(identity).await?;
                self.shared.store.remove_previous_key(identity)?;
            }
            Err(ClientError::CertificateExpired) => {
                // `CONTRACT.agent-identity.md` §8.1: the pending certificate expired before it was confirmed; renew
                // signed with the pending key, which `begin_recovery` moves to `previous`.
                warn!(
                    authority_id = %self.authority_id,
                    "Agent Identity pending certificate expired before confirmation; recovering"
                );
                store.begin_recovery(identity)?;
                self.renewal_retry.succeeded();
                self.recovery_signs_with_current = false;
            }
            Err(ClientError::Terminal(code)) => self.reject(code.as_str()),
            Err(error) => {
                warn!(authority_id = %self.authority_id, error = %error, "Agent Identity confirmation will retry");
                self.renewal_retry.failed(&self.shared.settings, error.retry_after());
            }
        }
        Ok(())
    }

    async fn check_in(&mut self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        let Some(signer) = self.current_signer(identity)? else {
            return Ok(());
        };
        let metadata = self.metadata();
        let result = self
            .shared
            .client
            .check_in(&identity.base_url, &signer, &metadata, None)
            .await;
        match result {
            Ok(response) => {
                if response.renewal_requested {
                    self.renewal_requested = true;
                }
                // UNTESTED: a config that can't be stored leaves the check-in due, so that its retry delivers the
                // config and renewal request again; when changing this, advance the schedule only after storing.
                if self.shared.store.update_config(identity, response.config)? {
                    info!(authority_id = %self.authority_id, "Agent Identity config updated");
                }
                self.config_revision
                    .store(config_revision(&identity.config), Ordering::Relaxed);
                self.check_in_retry.succeeded();
                self.next_check_in = Some(Instant::now() + self.check_in_interval());
            }
            Err(ClientError::CertificateExpired) => {
                // `CONTRACT.agent-identity.md` §5.4: renew at once, and check in again only after `confirm`.
                self.renewal_requested = true;
                self.check_in_after_confirm = true;
                self.next_check_in = None;
            }
            Err(ClientError::Terminal(code)) => self.reject(code.as_str()),
            Err(error) => {
                warn!(authority_id = %self.authority_id, error = %error, "Agent Identity check-in will retry");
                self.check_in_retry.failed(&self.shared.settings, error.retry_after());
            }
        }
        Ok(())
    }

    /// Handles what the identity's streams reported since the previous step.
    fn handle_notices(&mut self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        while let Some(notice) = self.notices.pop_front().or_else(|| self.streams.try_next_notice()) {
            match &notice {
                Notice::Lost => {
                    // UNTESTED: losing the last authenticated stream restarts the 1 h count before check-in resumes.
                    // When changing this, keep the count running from the loss, not from the runner's start.
                    // `crates/agent-identity/INTENT.md` ("Schedules"): with a channel URL, check in once no stream
                    // has authenticated for 1 h.
                    let check_in_at = Instant::now() + self.channel_failure_check_in_after();
                    self.next_check_in = self.next_check_in.map(|_| check_in_at);
                }
                // The step's reconciliation opens the stream.
                Notice::StreamNeeded => {}
                Notice::Terminal(code) => self.reject(code.as_str()),
                Notice::CertificateExpired { key_name } => {
                    if *key_name == identity.keys.current.key_name {
                        // `CONTRACT.md` §5.4: renew at once, signing with the expired certificate, and connect again
                        // only after `confirm`.
                        warn!(
                            authority_id = %self.authority_id,
                            "Agent Identity certificate expired; renewing before the agent channel reconnects"
                        );
                        self.renewal_requested = true;
                        self.channel_after_confirm = true;
                    }
                }
                Notice::RenewRequested { key_name } => {
                    // UNTESTED: a request on a stream of a key that a confirmed renewal replaced starts no renewal, and
                    // one during a renewal is satisfied when that renewal is confirmed, which clears the flag.
                    // When changing this, keep one renewal for each request.
                    if *key_name == identity.keys.current.key_name {
                        self.renewal_requested = true;
                    }
                }
                Notice::ConfigUpdate { link, id, config_json } => {
                    // UNTESTED: a pushed config that can't be stored stays queued and is not acknowledged, so that a
                    // later step stores it; when changing this, acknowledge only a config that is stored or not newer.
                    if let Err(error) = self.store_pushed_config(identity, *link, id, config_json) {
                        self.notices.push_front(notice.clone());
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    /// Stores a config pushed on the stream `link` if its revision is higher, then acknowledges it; the step applies
    /// it to the streams afterwards (`CONTRACT.md` §7.3 step 7).
    fn store_pushed_config(
        &mut self,
        identity: &mut StoredIdentity,
        link: LinkId,
        id: &str,
        config_json: &str,
    ) -> anyhow::Result<()> {
        let config = match client::parse_pushed_config(config_json) {
            Ok(config) => config,
            Err(error) => {
                // `CONTRACT.md` §5.2: a config with another version is a transient failure, and the stored config
                // stays; the authority sends it again after the next `Hello`.
                warn!(
                    authority_id = %self.authority_id,
                    %error,
                    "Ignoring an Agent Identity config pushed on the agent channel"
                );
                return Ok(());
            }
        };
        if self.shared.store.update_config(identity, config)? {
            info!(authority_id = %self.authority_id, "Agent Identity config updated");
        }
        self.streams.ack(link, id);
        Ok(())
    }

    /// Opens, keeps or drops the identity's streams for its state ([CONTRACT.md §7.3 "Sequence"][sequence] and
    /// [§8.1 "Agent renewal"][renewal]).
    ///
    /// [sequence]: ../../../docs/agent-identity/CONTRACT.md#73-sequence
    /// [renewal]: ../../../docs/agent-identity/CONTRACT.md#81-agent-renewal
    async fn reconcile_channel(&mut self, identity: &StoredIdentity) -> anyhow::Result<()> {
        let current = &identity.keys.current;
        let url = self.channel_url.clone().filter(|_| !self.channel_after_confirm);
        let want = match url {
            // `CONTRACT.md` §8.1 step 3: no stream opens while the outcome of a `confirm` may be unknown.
            _ if self.confirm_unknown => Want::Hold,
            Some(url) => Want::Stream {
                url,
                key_name: current.key_name.clone(),
            },
            None => Want::Nothing,
        };
        let Want::Stream { url, key_name } = want.clone() else {
            self.streams.reconcile(want).await;
            return Ok(());
        };
        if !self.streams.reconcile(want).await {
            return Ok(());
        }
        let Some(key) = device_key::open(self.shared.store.key_backend(), &key_name)? else {
            self.reject(KEY_LOST);
            return Ok(());
        };
        let target = Target {
            url: url.clone(),
            key: Arc::from(key),
            leaf_certificate_der: client::leaf_certificate_der(certificate_chain(current)?)?,
            hello: self.hello_fields(),
        };
        let shared = Arc::clone(&self.shared);
        self.streams
            .open(url, key_name, move || shared.channels.connect(target));
        Ok(())
    }

    /// Returns what each `Hello` carries: the metadata collected when it is sent, and the stored config revision
    /// (`CONTRACT.md` §3.1 and §7.3 step 7).
    fn hello_fields(&self) -> Arc<dyn Fn() -> HelloFields + Send + Sync> {
        let config_revision = Arc::clone(&self.config_revision);
        let override_path = self.shared.settings.metadata_override_path.clone();
        Arc::new(move || HelloFields {
            metadata: metadata::collect(env!("CARGO_PKG_VERSION"), override_path.as_deref())
                .into_iter()
                .collect(),
            config_revision: config_revision.load(Ordering::Relaxed),
        })
    }

    /// Latches a terminal outcome; the next step records it and stops this runner for good.
    ///
    /// `crates/agent-identity/INTENT.md` ("Identities"): the identity keeps its keys and slots until it is replaced.
    fn reject(&mut self, code: &'static str) {
        self.terminal = Some(code);
    }

    /// Returns a signer for the current key, or latches `key_lost` and returns `None` when the key no longer exists.
    ///
    /// `crates/agent-identity/INTENT.md` ("Identities"): an identity whose current key no longer exists in its key store
    /// is rejected with the code `key_lost`.
    fn current_signer(&mut self, identity: &StoredIdentity) -> anyhow::Result<Option<RequestSigner>> {
        let current = &identity.keys.current;
        // UNTESTED: a current key missing at run time rejects the identity as `key_lost` instead of retrying forever.
        // Start-up reconciliation has a test; this path doesn't.
        // When changing it, keep `None` distinct from an open error, which stays a retried local failure.
        let Some(key) = device_key::open(self.shared.store.key_backend(), &current.key_name)? else {
            self.reject(KEY_LOST);
            return Ok(None);
        };
        client::request_signer(Arc::from(key), certificate_chain(current)?).map(Some)
    }

    /// Opens a pending key, or returns `None` when it is unusable.
    ///
    /// `crates/agent-identity/INTENT.md` ("Stored identities"): a pending key is unusable when it is missing from its
    /// store, refused when opened, or doesn't match its certificate's public key.
    fn open_usable(&self, record: &KeyRecord) -> Option<Box<dyn DeviceKey>> {
        let key = match device_key::open(self.shared.store.key_backend(), &record.key_name) {
            Ok(Some(key)) => key,
            Ok(None) => {
                warn!(authority_id = %self.authority_id, "Agent Identity pending key is missing");
                return None;
            }
            Err(error) => {
                warn!(
                    authority_id = %self.authority_id,
                    error = format!("{error:#}"),
                    "Agent Identity pending key cannot be opened"
                );
                return None;
            }
        };
        if let Some(chain) = &record.certificate_chain
            && client::validate_certificate_chain(chain, &key.public_key()).is_err()
        {
            warn!(
                authority_id = %self.authority_id,
                "Agent Identity pending key does not match its certificate"
            );
            return None;
        }
        Some(key)
    }

    fn metadata(&self) -> metadata::Metadata {
        metadata::collect(
            env!("CARGO_PKG_VERSION"),
            self.shared.settings.metadata_override_path.as_deref(),
        )
    }

    fn renewal_at(&mut self, identity: &StoredIdentity, now: Instant) -> anyhow::Result<Instant> {
        let current = &identity.keys.current;
        let (not_before, not_after) = client::leaf_validity(certificate_chain(current)?)?;
        let jitter = match &self.renewal_jitter {
            Some((key_name, jitter)) if *key_name == current.key_name => *jitter,
            _ => {
                let jitter = if self.shared.settings.disable_jitter.unwrap_or_default() {
                    0.0
                } else {
                    rand::thread_rng().gen_range(0.0..=1.0)
                };
                self.renewal_jitter = Some((current.key_name.clone(), jitter));
                jitter
            }
        };
        let loaded_at = self.load_times.loaded_at(&current.key_name, SystemTime::now());
        let renewal_after = self.shared.settings.renewal_after_secs.map(Duration::from_secs);
        let renewal_at = schedule::renewal_time(not_before, not_after, loaded_at, renewal_after, jitter);
        Ok(instant_at(renewal_at, now))
    }

    /// Restarts the channel-failure check-in delay when a check-in adds or changes a usable channel URL.
    fn follow_channel_url(&mut self, identity: &StoredIdentity, now: Instant) {
        let channel_url = self.usable_channel_url(identity);
        if channel_url != self.channel_url {
            if channel_url.is_some() {
                self.next_check_in = self.next_check_in.map(|_| now + self.channel_failure_check_in_after());
            }
            self.channel_url = channel_url;
        }
    }

    fn usable_channel_url(&mut self, identity: &StoredIdentity) -> Option<Url> {
        match schedule::channel_url(&identity.config) {
            ChannelUrl::Usable(url) => Some(url),
            ChannelUrl::Absent => None,
            ChannelUrl::Malformed => {
                if self.warned_malformed_config.as_ref() != Some(&identity.config) {
                    warn!(
                        authority_id = %self.authority_id,
                        "Agent Identity channel URL is not an absolute https URL without a query or fragment; ignoring it"
                    );
                    self.warned_malformed_config = Some(identity.config.clone());
                }
                None
            }
        }
    }

    fn check_in_interval(&self) -> Duration {
        let settings = &self.shared.settings;
        let base = settings
            .check_in_interval_secs
            .map_or(CHECK_IN_INTERVAL, Duration::from_secs);
        // `devolutions-agent/src/identity/INTENT.md` ("Configuration"): either check-in knob disables the jitter.
        let jitter = if settings.disable_jitter.unwrap_or_default()
            || settings.check_in_interval_secs.is_some()
            || settings.channel_failure_check_in_after_secs.is_some()
        {
            0.5
        } else {
            rand::thread_rng().gen_range(0.0..=1.0)
        };
        schedule::check_in_interval(base, jitter)
    }

    fn channel_failure_check_in_after(&self) -> Duration {
        self.shared
            .settings
            .channel_failure_check_in_after_secs
            .map_or(CHANNEL_FAILURE_CHECK_IN_AFTER, Duration::from_secs)
    }
}

/// When this run stored or loaded the certificate of each key the identity holds, by key name.
#[derive(Default)]
struct LoadTimes(HashMap<String, SystemTime>);

impl LoadTimes {
    /// Records that this run stored or loaded the certificate of `key_name` at `at`.
    fn record(&mut self, key_name: &str, at: SystemTime) {
        self.0.insert(key_name.to_owned(), at);
    }

    /// Returns when this run stored or loaded the certificate of `key_name`, recording `now` when it has no record.
    fn loaded_at(&mut self, key_name: &str, now: SystemTime) -> SystemTime {
        *self.0.entry(key_name.to_owned()).or_insert(now)
    }

    /// Forgets the keys the identity no longer holds.
    fn retain(&mut self, keys: &KeySlots) {
        self.0.retain(|key_name, _| {
            std::iter::once(&keys.current)
                .chain(keys.pending.iter())
                .chain(keys.previous.iter())
                .any(|record| record.key_name == *key_name)
        });
    }
}

fn certificate_chain(record: &KeyRecord) -> anyhow::Result<&[String]> {
    record
        .certificate_chain
        .as_deref()
        .context("identity key has no certificate chain")
}

/// Returns the revision of a stored config, which the store only accepts with one.
fn config_revision(config: &Value) -> u64 {
    config.get("revision").and_then(Value::as_u64).unwrap_or_default()
}

fn later(at: Instant, retry_at: Option<Instant>) -> Instant {
    retry_at.map_or(at, |retry_at| retry_at.max(at))
}

/// Converts a wall-clock time into an instant relative to `now`, at most `MAX_WAIT` ahead.
///
/// A time that has passed returns `now` itself, so that a caller comparing against `now` sees it as due.
fn instant_at(at: SystemTime, now: Instant) -> Instant {
    match at.duration_since(SystemTime::now()) {
        Ok(delay) => now.checked_add(delay.min(MAX_WAIT)).unwrap_or(now),
        Err(_) => now,
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn a_past_renewal_time_is_due_at_the_caller_s_now() {
        // A renewal time that has passed must compare due against the instant the step read, or the step spins.
        let now = Instant::now();
        assert_eq!(instant_at(SystemTime::now() - Duration::from_secs(1), now), now);
    }

    #[test]
    fn a_certificate_keeps_the_time_it_was_stored_until_it_is_scheduled() {
        // `crates/agent-identity/INTENT.md` ("Schedules"): the anchor is the earlier of `notBefore` and the moment the
        // agent stored or loaded the certificate, so a pending certificate confirmed 6 s after renew stored it keeps
        // the time of storage once it becomes current.
        let stored_at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut loads = LoadTimes::default();
        loads.record("renewed", stored_at);
        assert_eq!(
            loads.loaded_at("renewed", stored_at + Duration::from_secs(6)),
            stored_at
        );
    }
}
