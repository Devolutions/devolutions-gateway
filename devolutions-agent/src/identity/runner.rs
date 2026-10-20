//! The per-authority runner: renewal, confirmation and check-in of one stored identity.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use agent_identity::client::{self, Client, ClientError, RequestSigner, TerminalCode};
use agent_identity::schedule::{self, ChannelUrl};
use agent_identity::state::{KeyRecord, Store, StoredIdentity};
use agent_identity::{csr, metadata};
use anyhow::Context as _;
use device_key::DeviceKey;
use devolutions_gateway_task::ShutdownSignal;
use rand::Rng as _;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use super::RetryState;
use super::config::IdentityDebugConf;

const CHECK_IN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const CHANNEL_FAILURE_CHECK_IN_AFTER: Duration = Duration::from_secs(60 * 60);
/// Bounds every wait, so that a wall-clock change delays a scheduled action by at most this long.
const MAX_WAIT: Duration = Duration::from_secs(60);

/// The state and services every runner shares with pending enrollment.
pub(super) struct Shared {
    pub(super) store: Store,
    pub(super) client: Client,
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
    /// Whether pending-key recovery signs with the current key after the expired pending key drew `identity_unknown`.
    recovery_signs_with_current: bool,
    /// The renewal jitter sample, drawn once for each current key.
    renewal_jitter: Option<(String, f64)>,
    /// `None` while a check-in waits for a renewal to be confirmed.
    next_check_in: Option<Instant>,
    check_in_after_confirm: bool,
    channel_url: Option<Url>,
    warned_malformed_config: Option<Value>,
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
            recovery_signs_with_current: false,
            renewal_jitter: None,
            next_check_in: None,
            check_in_after_confirm: false,
            channel_url: None,
            warned_malformed_config: None,
        };
        // `crates/agent-identity/INTENT.md` ("Schedules"): without a channel URL, check in when the runner starts;
        // with one, once no stream has authenticated for 1 h, counted from the runner's start.
        let now = Instant::now();
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
            tokio::select! {
                _ = tokio::time::sleep_until(wake.into()) => {}
                _ = shutdown.wait() => return,
            }
        }
    }

    /// Takes the next action of the identity, and returns when to take the following one, or `None` to stop.
    async fn step(&mut self) -> anyhow::Result<Option<Instant>> {
        let store = &self.shared.store;
        let Some(mut identity) = store.read_identity(self.authority_id)? else {
            return Ok(None);
        };
        if identity.identity_id != self.identity_id || identity.rejected.is_some() {
            return Ok(None);
        }
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
        if confirming || recovering {
            // `CONTRACT.md` §8.1: while the outcome of a `confirm` is unknown, the agent sends no other signed request.
            // During pending-key recovery, it is still unknown whether an earlier `confirm` retired the current key.
            if !self.renewal_retry.is_due() {
                return Ok(self.renewal_retry.next_attempt);
            }
            if confirming {
                self.confirm(&mut identity, recovering).await?;
            } else {
                self.renew(&mut identity, true).await?;
            }
            return Ok(Some(Instant::now()));
        }

        self.follow_channel_url(&identity, now);
        let renewal_at = if identity.keys.pending.is_some() || self.renewal_requested {
            now
        } else {
            self.renewal_at(&identity, now)?
        };
        let renewal_wake = later(renewal_at, self.renewal_retry.next_attempt);
        if renewal_wake <= now {
            self.renew(&mut identity, false).await?;
            return Ok(Some(Instant::now()));
        }
        let check_in_wake = self
            .next_check_in
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
    /// in `previous`, then with the current key once that draws `identity_unknown` (`CONTRACT.md` §8.1).
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
                // `CONTRACT.md` §8.1: without a usable pending key, renew with a fresh key signed by the current
                // certificate.
                store.remove_previous_key(identity)?;
                return Ok(());
            };
            client::request_signer(Arc::from(key), certificate_chain(&expired)?)?
        } else {
            self.signer(&identity.keys.current)?
        };
        let csr = csr::create(new_key.as_ref()).context("create renewal CSR")?;
        let result = self
            .shared
            .client
            .renew(
                &identity.base_url,
                &signer,
                &csr,
                &new_key.public_key(),
                &self.metadata(),
                None,
            )
            .await;
        match result {
            Ok(response) => {
                self.shared
                    .store
                    .store_pending_chain(identity, response.certificate_chain)?;
                self.renewal_retry.succeeded();
                self.recovery_signs_with_current = false;
            }
            Err(ClientError::Terminal(TerminalCode::IdentityUnknown)) if signs_with_expired_pending => {
                // `CONTRACT.md` §8.1: the server holds neither certificate, so retry the same renewal signed with
                // the old current key.
                warn!(
                    authority_id = %self.authority_id,
                    "Agent Identity recovery renewal is unknown to the authority; retrying with the current key"
                );
                self.recovery_signs_with_current = true;
            }
            // `CONTRACT.md` §5.4 and §8.1: on renew, `certificate_expired` means beyond grace, which is terminal.
            Err(ClientError::CertificateExpired) => self.reject(identity, "certificate_expired")?,
            Err(ClientError::Terminal(code)) => self.reject(identity, code.as_str())?,
            Err(error) => {
                warn!(authority_id = %self.authority_id, reason = %error, "Agent Identity renewal will retry");
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
        match self.shared.client.confirm(&identity.base_url, &signer, None).await {
            Ok(()) => {
                if recovering {
                    // `crates/agent-identity/INTENT.md` ("Stored identities"): once the next `confirm` succeeds,
                    // delete the expired pending key, then promote as usual.
                    store.remove_previous_key(identity)?;
                }
                store.promote_pending(identity)?;
                self.renewal_retry.succeeded();
                self.renewal_requested = false;
                if std::mem::take(&mut self.check_in_after_confirm) {
                    self.next_check_in = Some(Instant::now());
                }
                info!(
                    authority_id = %self.authority_id,
                    identity_id = %self.identity_id,
                    "Agent Identity certificate renewed"
                );
                store.remove_previous_key(identity)?;
            }
            Err(ClientError::CertificateExpired) => {
                // `CONTRACT.md` §8.1: the pending certificate expired before it was confirmed; renew signed with
                // the pending key, which `begin_recovery` moves to `previous`.
                warn!(
                    authority_id = %self.authority_id,
                    "Agent Identity pending certificate expired before confirmation; recovering"
                );
                store.begin_recovery(identity)?;
                self.renewal_retry.succeeded();
                self.recovery_signs_with_current = false;
            }
            Err(ClientError::Terminal(code)) => self.reject(identity, code.as_str())?,
            Err(error) => {
                warn!(authority_id = %self.authority_id, reason = %error, "Agent Identity confirmation will retry");
                self.renewal_retry.failed(&self.shared.settings, error.retry_after());
            }
        }
        Ok(())
    }

    async fn check_in(&mut self, identity: &mut StoredIdentity) -> anyhow::Result<()> {
        let signer = self.signer(&identity.keys.current)?;
        let result = self
            .shared
            .client
            .check_in(&identity.base_url, &signer, &self.metadata(), None)
            .await;
        match result {
            Ok(response) => {
                self.check_in_retry.succeeded();
                self.next_check_in = Some(Instant::now() + self.check_in_interval());
                if self.shared.store.update_config(identity, response.config)? {
                    info!(authority_id = %self.authority_id, "Agent Identity config updated");
                }
                if response.renewal_requested {
                    self.renewal_requested = true;
                }
            }
            Err(ClientError::CertificateExpired) => {
                // `CONTRACT.md` §5.4: renew at once, and check in again only after `confirm`.
                self.renewal_requested = true;
                self.check_in_after_confirm = true;
                self.next_check_in = None;
            }
            Err(ClientError::Terminal(code)) => self.reject(identity, code.as_str())?,
            Err(error) => {
                warn!(authority_id = %self.authority_id, reason = %error, "Agent Identity check-in will retry");
                self.check_in_retry.failed(&self.shared.settings, error.retry_after());
            }
        }
        Ok(())
    }

    /// Records a terminal outcome, which stops this runner for good.
    ///
    /// `crates/agent-identity/INTENT.md` ("Identities"): the identity keeps its keys and slots until it is replaced.
    fn reject(&self, identity: &mut StoredIdentity, code: &str) -> anyhow::Result<()> {
        self.shared.store.reject_identity(identity, code)?;
        warn!(
            authority_id = %self.authority_id,
            identity_id = %self.identity_id,
            code,
            "The authority rejected the Agent Identity; it stops renewing and checking in"
        );
        Ok(())
    }

    fn signer(&self, record: &KeyRecord) -> anyhow::Result<RequestSigner> {
        let key: Box<dyn DeviceKey> = device_key::open(self.shared.store.key_backend(), &record.key_name)?
            .context("identity key is missing from its key store")?;
        client::request_signer(Arc::from(key), certificate_chain(record)?)
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
        let renewal_after = self.shared.settings.renewal_after_secs.map(Duration::from_secs);
        let renewal_at = schedule::renewal_time(not_before, not_after, renewal_after, jitter);
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

fn certificate_chain(record: &KeyRecord) -> anyhow::Result<&[String]> {
    record
        .certificate_chain
        .as_deref()
        .context("identity key has no certificate chain")
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
    use super::*;

    #[test]
    fn a_past_renewal_time_is_due_at_the_caller_s_now() {
        // A renewal time that has passed must compare due against the instant the step read, or the step spins.
        let now = Instant::now();
        assert_eq!(instant_at(SystemTime::now() - Duration::from_secs(1), now), now);
        assert_eq!(
            instant_at(SystemTime::now() + Duration::from_secs(86_400), now),
            now + MAX_WAIT
        );
    }
}
