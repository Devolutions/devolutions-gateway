//! Agent Identity in the agent binary: the identity service task, the `identity` command and its configuration.

mod channel;
pub mod cli;
pub mod config;
mod runner;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_channel_client::{Backoff, ChannelClient, uniform_jitter};
use agent_identity::client::{Client, ClientError, PermanentCode, TerminalCode};
use agent_identity::pending::{self, PendingRead};
use agent_identity::state::{
    EnrolledIdentity, EnrollmentDiscardReason, IDENTITY_KEY_PREFIX, KeyRecord, KeySlots, PendingDiscard, Store,
    StoredIdentity, UntrustedStoredIdentity,
};
use agent_identity::token::Token;
use agent_identity::{csr, metadata};
use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use device_key::{BackendUnavailable, KeyBackend};
use devolutions_agent_shared::get_data_dir;
use devolutions_gateway_task::{ShutdownSignal, Task};
use rand::Rng as _;
use sysevent::SystemEventSink;
use tokio::time::sleep;

use self::config::{IdentityDebugConf, IdentityKeyBackend};
use self::runner::{Runners, Shared};
use crate::config::{Conf, ConfHandle};

pub struct IdentityTask {
    conf_handle: ConfHandle,
    system_events: Arc<dyn SystemEventSink>,
}

impl IdentityTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self {
            conf_handle,
            system_events: Arc::clone(&crate::SYSTEM_LOGGER),
        }
    }
}

#[async_trait]
impl Task for IdentityTask {
    type Output = anyhow::Result<()>;
    const NAME: &'static str = "identity";

    async fn run(self, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        run_identity(
            &self.conf_handle.get_conf(),
            get_data_dir(),
            self.system_events.as_ref(),
            shutdown,
        )
        .await
    }
}

async fn run_identity(
    conf: &Conf,
    data_dir: Utf8PathBuf,
    system_events: &dyn SystemEventSink,
    mut shutdown: ShutdownSignal,
) -> anyhow::Result<()> {
    let settings = conf.debug.identity.clone().unwrap_or_default();
    let poll_interval = Duration::from_millis(settings.pending_poll_interval_ms.unwrap_or(5_000).max(1));
    let mut last_store_error = None;
    let mut last_trust_error = None;

    loop {
        let backend = match conf.identity.key_backend {
            IdentityKeyBackend::File => Store::file_backend(&data_dir),
            IdentityKeyBackend::WindowsSoftwareProvider => KeyBackend::WindowsSoftwareProvider,
        };
        let store = Store::new(
            data_dir.clone(),
            backend,
            settings
                .key_name_prefix
                .clone()
                .unwrap_or_else(|| IDENTITY_KEY_PREFIX.to_owned()),
            settings.acl_grant_current_user.unwrap_or_default(),
        )
        .context("initialize Agent Identity store")
        .and_then(|store| {
            store.reconcile().context("reconcile Agent Identity store")?;
            Ok(store)
        });
        let store = match store {
            Ok(store) => store,
            Err(error) => {
                if let Some(unavailable) = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<BackendUnavailable>())
                {
                    // `crates/agent-identity/INTENT.md` ("Identities"): never retry or fall back to another backend.
                    error!(
                        backend = unavailable.backend,
                        error = format!("{error:#}"),
                        "Agent Identity key backend is unavailable; Agent Identity is stopped"
                    );
                    if let Err(emit_error) = system_events.emit(agent_sysevent_codes::identity_key_backend_unavailable(
                        unavailable.backend,
                        &error,
                    )) {
                        warn!(error = %emit_error, "Cannot report the Agent Identity key backend failure to the system log");
                    }
                    return Ok(());
                }
                if log_is_due(&mut last_store_error) {
                    if let Some(untrusted) = error
                        .chain()
                        .find_map(|cause| cause.downcast_ref::<UntrustedStoredIdentity>())
                    {
                        // UNTESTED: this log names the authority directory or identity file and how to fix it, because
                        // the agent never repairs it and stays stopped until an administrator does.
                        // No test captures service logs; when changing this, keep the path and the fix in the log.
                        error!(
                            error = format!("{error:#}"),
                            path = %untrusted.path,
                            "Agent Identity is stopped until this authority directory or identity.json is a plain directory or file owned by the service account with no access for other users; the agent never repairs it"
                        );
                    } else {
                        error!(
                            error = format!("{error:#}"),
                            directory = %data_dir.join("identity"),
                            "Agent Identity state is unavailable; fix the identity directory ownership and ACL for the service account"
                        );
                    }
                }
                if wait_or_stop(&mut shutdown, poll_interval).await {
                    return Ok(());
                }
                continue;
            }
        };
        let clients = Client::new(conf.proxy.to_proxy_config(), settings.extra_trusted_root.as_deref())
            .and_then(|client| Ok((client, channel_client(conf, &settings)?)));
        let (client, channels) = match clients {
            Ok(clients) => clients,
            Err(error) => {
                if log_is_due(&mut last_trust_error) {
                    warn!(
                        error = format!("{error:#}"),
                        "Cannot initialize Agent Identity HTTPS trust; retrying"
                    );
                }
                if wait_or_stop(&mut shutdown, poll_interval).await {
                    return Ok(());
                }
                continue;
            }
        };

        let shared = Arc::new(Shared {
            store,
            client,
            channels,
            settings: settings.clone(),
        });
        let mut runners = Runners::new(Arc::clone(&shared), shutdown.clone());
        match shared.store.list_identities() {
            Ok(identities) => {
                for identity in &identities {
                    runners.start(identity);
                }
            }
            Err(error) => {
                error!(
                    error = format!("{error:#}"),
                    "Cannot list stored Agent Identities; check the identity directory ownership and ACL"
                );
            }
        }
        let stopped = run_pending_enrollments(&shared, &mut runners, &data_dir, poll_interval, &mut shutdown).await;
        // UNTESTED: dropping the runners aborts every runner task and, with it, its agent channel streams.
        // Tests check that the pending poll returns, not that a live runner stops; when changing this, stop every runner
        // and its streams before returning to start-up.
        drop(runners);
        match stopped {
            Stopped::Shutdown => return Ok(()),
            Stopped::Untrusted => {}
        }
    }
}

/// Why pending enrollment stopped.
enum Stopped {
    Shutdown,
    /// An authority directory or `identity.json` failed its check, which stops all identity processing until it is
    /// fixed.
    Untrusted,
}

fn log_is_due(last: &mut Option<Instant>) -> bool {
    if last.is_some_and(|last| last.elapsed() < Duration::from_secs(60)) {
        false
    } else {
        *last = Some(Instant::now());
        true
    }
}

/// Creates the agent channel client, which trusts and reaches authorities as the identity HTTP client does.
///
/// `devolutions-agent/src/identity/INTENT.md` ("Configuration"): `disable_jitter` and `backoff_max_secs` apply to the
/// channel's reconnect backoff as to every other identity retry.
fn channel_client(conf: &Conf, settings: &IdentityDebugConf) -> anyhow::Result<ChannelClient> {
    let extra_trusted_roots = match &settings.extra_trusted_root {
        Some(path) => {
            let pem = std::fs::read(path).context("read the extra trusted root")?;
            rustls_pemfile::certs(&mut pem.as_slice())
                .collect::<std::io::Result<Vec<_>>>()
                .context("parse the extra trusted root")?
        }
        None => Vec::new(),
    };
    let jitter: Arc<dyn Fn() -> f64 + Send + Sync> = if settings.disable_jitter.unwrap_or_default() {
        Arc::new(|| 1.0)
    } else {
        Arc::new(uniform_jitter)
    };
    let backoff = Backoff {
        max: settings
            .backoff_max_secs
            .map(|seconds| Duration::from_secs(seconds.max(1))),
        jitter,
        ..Backoff::default()
    };
    ChannelClient::new(
        conf.proxy.to_proxy_config(),
        &extra_trusted_roots,
        agent_channel_client::Settings {
            backoff,
            ..agent_channel_client::Settings::default()
        },
    )
}

async fn wait_or_stop(shutdown: &mut ShutdownSignal, duration: Duration) -> bool {
    tokio::select! {
        _ = shutdown.wait() => true,
        _ = sleep(duration) => false,
    }
}

enum PendingOutcome {
    Completed,
    Enrolled(Box<StoredIdentity>),
    Retry { retry_after: Option<Duration> },
}

#[derive(Default)]
struct RetryState {
    failures: u32,
    next_attempt: Option<Instant>,
}

impl RetryState {
    fn is_due(&self) -> bool {
        self.next_attempt.is_none_or(|next| Instant::now() >= next)
    }

    fn succeeded(&mut self) {
        *self = Self::default();
    }

    fn failed(&mut self, settings: &IdentityDebugConf, retry_after: Option<Duration>) {
        let now = Instant::now();
        let max_backoff = Duration::from_secs(settings.backoff_max_secs.unwrap_or(3600).max(1));
        self.failures = self.failures.saturating_add(1);
        let jitter = if settings.disable_jitter.unwrap_or_default() {
            1.0
        } else {
            rand::thread_rng().gen_range(0.5..=1.5)
        };
        let backoff = backoff(self.failures, jitter, max_backoff);
        let delay = retry_delay(max_backoff, backoff, retry_after);
        self.next_attempt = now.checked_add(delay).or_else(|| now.checked_add(max_backoff));
    }
}

/// Returns the delay after the `failure`-th consecutive failure, counted from 1, scaled by `jitter` and capped at
/// `maximum`.
fn backoff(failure: u32, jitter: f64, maximum: Duration) -> Duration {
    // The exponent stops at 62 so that 2^62 s times the largest jitter still fits a `Duration`.
    Duration::from_secs(1u64 << failure.min(62))
        .mul_f64(jitter)
        .min(maximum)
}

fn retry_delay(maximum: Duration, backoff: Duration, retry_after: Option<Duration>) -> Duration {
    backoff.max(retry_after.unwrap_or_default()).min(maximum)
}

async fn run_pending_enrollments(
    shared: &Shared,
    runners: &mut Runners,
    data_dir: &Utf8Path,
    poll_interval: Duration,
    shutdown: &mut ShutdownSignal,
) -> Stopped {
    let Shared {
        store,
        client,
        settings,
        ..
    } = shared;
    let mut retries: HashMap<Utf8PathBuf, RetryState> = HashMap::new();
    let mut last_list_error = None;
    loop {
        // `crates/agent-identity/INTENT.md` ("Local state"): an authority directory or `identity.json` that fails its
        // check stops all identity processing; start-up reports it and waits until it is fixed.
        if store.check_stored_identities().is_err() {
            return Stopped::Untrusted;
        }
        match pending::list(data_dir) {
            Ok(paths) => {
                let present: HashSet<&Utf8PathBuf> = paths.iter().collect();
                retries.retain(|path, _| present.contains(path));
                for path in paths {
                    if retries.get(&path).is_some_and(|retry| !retry.is_due()) {
                        continue;
                    }
                    let outcome = tokio::select! {
                        result = process_pending(store, client, &path, settings) => result,
                        _ = shutdown.wait() => return Stopped::Shutdown,
                    };
                    match outcome {
                        Ok(PendingOutcome::Completed) => {
                            retries.remove(&path);
                        }
                        Ok(PendingOutcome::Enrolled(identity)) => {
                            retries.remove(&path);
                            runners.start(&identity);
                        }
                        Ok(PendingOutcome::Retry { retry_after }) => {
                            retries.entry(path).or_default().failed(settings, retry_after);
                        }
                        Err(error) => {
                            warn!(
                                error = format!("{error:#}"),
                                "Cannot process Agent Identity pending enrollment"
                            );
                            retries.entry(path).or_default().failed(settings, None);
                        }
                    }
                }
            }
            Err(error) => {
                if log_is_due(&mut last_list_error) {
                    error!(
                        error = format!("{error:#}"),
                        directory = %pending::directory(data_dir),
                        "Cannot list Agent Identity pending files; check the identity directory ownership and ACL"
                    );
                }
            }
        }
        if wait_or_stop(shutdown, poll_interval).await {
            return Stopped::Shutdown;
        }
    }
}

async fn process_pending(
    store: &Store,
    client: &Client,
    path: &Utf8Path,
    settings: &IdentityDebugConf,
) -> anyhow::Result<PendingOutcome> {
    let token = match pending::read(path, settings.acl_grant_current_user.unwrap_or_default()) {
        Ok(PendingRead::Ready(token)) => token,
        Ok(_) => {
            // UNTESTED: Unusable files log warnings, while DPAPI failures log errors without token material.
            // State tests cover file removal but do not capture service logs.
            // When changing these outcomes, check both log levels and keep token contents out of the messages.
            match store.discard_pending_file(path)? {
                Some(PendingDiscard::MalformedToken) => {
                    warn!("Discarded malformed Agent Identity enrollment token");
                }
                Some(PendingDiscard::Unusable) => {
                    warn!("Discarded unusable Agent Identity pending file");
                }
                #[cfg(windows)]
                Some(PendingDiscard::Undecryptable) => {
                    error!("Could not decrypt Agent Identity pending file; discarded it");
                }
                None => {}
            }
            return Ok(PendingOutcome::Completed);
        }
        Err(error) => return Err(error),
    };
    enroll_pending(store, client, &token, settings).await
}

async fn enroll_pending(
    store: &Store,
    client: &Client,
    token: &Token,
    settings: &IdentityDebugConf,
) -> anyhow::Result<PendingOutcome> {
    let Some((record, key)) = store.begin_enrollment(token)? else {
        return Ok(PendingOutcome::Completed);
    };
    // UNTESTED: the enrollment CSR names the token's `u` without trailing slashes, which the authority compares with the
    // `u` of the token it receives (`CONTRACT.agent-identity.md` §4).
    // No agent test captures the request it sends; when changing this, keep passing `Token::base_url`.
    let csr_der = csr::create(key.as_ref(), token.base_url()).context("create enrollment CSR")?;
    let metadata = metadata::collect(env!("CARGO_PKG_VERSION"), settings.metadata_override_path.as_deref());
    let hash = token.sha256_hex();
    match client.enroll(token, &csr_der, &metadata, key.as_ref()).await {
        Ok(response) => {
            let identity = StoredIdentity {
                version: 1,
                authority_id: response.authority_id,
                identity_id: response.identity_id,
                base_url: token.base_url().to_owned(),
                config: response.config,
                token_sha256: hash.clone(),
                rejected: None,
                keys: KeySlots {
                    current: KeyRecord {
                        key_name: record.key_name,
                        certificate_chain: Some(response.certificate_chain),
                    },
                    pending: None,
                    previous: None,
                },
            };
            match store.store_enrolled_identity(&identity)? {
                EnrolledIdentity::Stored => {}
                EnrolledIdentity::AuthorityConflict => {
                    // UNTESTED: this warning names the authority but no base URL and no token material, because the
                    // token's base URL comes from the token; no test captures service logs, so keep both out when
                    // changing it.
                    warn!(
                        authority_id = %identity.authority_id,
                        "Discarded Agent Identity enrollment claiming a known authority from another base URL"
                    );
                    return Ok(PendingOutcome::Completed);
                }
            }
            info!(authority_id = %identity.authority_id, identity_id = %identity.identity_id, "Agent Identity enrolled");
            // UNTESTED: the identity is stored, so its runner starts even when cleanup fails.
            // A remaining pending file is cleaned up when it is polled again, and a remaining in-progress record at the
            // next start-up; when changing this, never let cleanup decide whether the runner starts.
            if let Err(error) = store.finish_enrollment(&hash, identity.authority_id) {
                warn!(
                    error = format!("{error:#}"),
                    "Cannot clean up a completed Agent Identity enrollment"
                );
            }
            Ok(PendingOutcome::Enrolled(Box::new(identity)))
        }
        Err(ClientError::Permanent(code)) => {
            let reason = match code {
                PermanentCode::TokenInvalid => EnrollmentDiscardReason::TokenInvalid,
                PermanentCode::TokenExhausted => EnrollmentDiscardReason::TokenExhausted,
                PermanentCode::TokenExpired => EnrollmentDiscardReason::TokenExpired,
                PermanentCode::AuthorityUrlMismatch => EnrollmentDiscardReason::AuthorityUrlMismatch,
            };
            store.discard_enrollment(&hash, reason)?;
            warn!(
                reason = code.as_str(),
                "Discarded permanently rejected Agent Identity enrollment"
            );
            Ok(PendingOutcome::Completed)
        }
        Err(ClientError::Terminal(TerminalCode::IdentityRevoked)) => {
            store.discard_enrollment(&hash, EnrollmentDiscardReason::IdentityRevoked)?;
            warn!("Discarded revoked Agent Identity enrollment");
            Ok(PendingOutcome::Completed)
        }
        Err(error) => {
            warn!(reason = %error, "Agent Identity enrollment will retry");
            Ok(PendingOutcome::Retry {
                retry_after: error.retry_after(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[tokio::test]
    async fn unavailable_key_backend_stops_identity_after_one_system_event() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Identities
        // An unavailable backend is reported once and stops the identity feature before it touches any state; the
        // Windows software provider never exists on this platform.
        let data_dir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("identity-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&data_dir)?;
        let conf = Conf::from_conf_file(&serde_json::from_value(serde_json::json!({
            "Identity": { "KeyBackend": "WindowsSoftwareProvider" }
        }))?)?;
        let events = RecordingSink::default();
        let (_shutdown_handle, shutdown) = devolutions_gateway_task::ShutdownHandle::new();

        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            run_identity(&conf, data_dir.clone(), &events, shutdown),
        )
        .await;
        let leftovers = std::fs::read_dir(&data_dir)?.count();
        std::fs::remove_dir_all(&data_dir)?;

        outcome.context("identity task kept running")??;
        let entries = events.0.lock();
        assert_eq!(entries.len(), 1);
        // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
        assert_eq!(entries[0].event_code, Some(1100));
        assert!(
            entries[0]
                .fields
                .contains(&("backend".to_owned(), "WindowsSoftwareProvider".to_owned())),
            "{:?}",
            entries[0].fields
        );
        assert_eq!(leftovers, 0);
        Ok(())
    }

    #[derive(Default)]
    struct RecordingSink(parking_lot::Mutex<Vec<sysevent::Entry>>);

    impl SystemEventSink for RecordingSink {
        fn emit(&self, entry: sysevent::Entry) -> Result<(), sysevent::SysEventError> {
            self.0.lock().push(entry);
            Ok(())
        }

        fn flush(&self) -> Result<(), sysevent::SysEventError> {
            Ok(())
        }
    }

    /// A data directory under the system temporary directory, whose short path keeps key files under the Windows path
    /// limit wherever the repository is checked out.
    struct TestDataDir(Utf8PathBuf);

    impl TestDataDir {
        fn new() -> anyhow::Result<Self> {
            let path = Utf8PathBuf::from_path_buf(std::env::temp_dir())
                .map_err(|_| anyhow::anyhow!("the temporary directory path is not UTF-8"))?
                .join(format!("ai-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn store(&self) -> anyhow::Result<Store> {
            Store::new(
                self.0.clone(),
                Store::file_backend(&self.0),
                IDENTITY_KEY_PREFIX.to_owned(),
                true,
            )
        }

        /// Creates an authority directory with default permissions, which is not the form the agent provisions: it is
        /// open to group and other users on Unix, and its DACL is inherited rather than protected on Windows.
        fn put_untrusted_authority_directory(&self) -> anyhow::Result<Utf8PathBuf> {
            let path = self
                .0
                .join("identity")
                .join("authorities")
                .join(uuid::Uuid::new_v4().to_string());
            std::fs::create_dir(&path)?;
            #[cfg(unix)]
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
            Ok(path)
        }

        /// Stores an identity, then gives its `identity.json` default permissions, which is not the form the agent
        /// provisions: it is open to group and other users on Unix, and its DACL is inherited rather than protected on
        /// Windows.
        fn put_untrusted_identity_file(&self) -> anyhow::Result<Utf8PathBuf> {
            let store = self.store()?;
            let identity = StoredIdentity {
                version: 1,
                authority_id: uuid::Uuid::new_v4(),
                identity_id: uuid::Uuid::new_v4(),
                base_url: "https://127.0.0.1:9".to_owned(),
                config: serde_json::json!({ "version": 1, "revision": 1 }),
                token_sha256: "1".repeat(64),
                rejected: None,
                keys: KeySlots {
                    current: KeyRecord {
                        key_name: device_key::new_key_name(IDENTITY_KEY_PREFIX),
                        certificate_chain: Some(vec!["YWJj".to_owned()]),
                    },
                    pending: None,
                    previous: None,
                },
            };
            store.store_enrolled_identity(&identity)?;
            let path = store.identity_path(identity.authority_id);
            let contents = std::fs::read(&path)?;
            std::fs::remove_file(&path)?;
            std::fs::write(&path, contents)?;
            #[cfg(unix)]
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
            Ok(path)
        }
    }

    impl Drop for TestDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_conf() -> anyhow::Result<Conf> {
        Conf::from_conf_file(&serde_json::from_value(serde_json::json!({
            "Identity": { "KeyBackend": "File" },
            "__debug__": { "identity": { "pending_poll_interval_ms": 10, "acl_grant_current_user": true } }
        }))?)
    }

    #[tokio::test]
    async fn an_untrusted_authority_directory_holds_pending_enrollment_until_it_is_fixed() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Local state
        // An authority directory that fails the check stops all identity processing until it is fixed, so no pending
        // file is processed meanwhile, and processing resumes without a restart.
        use base64::Engine as _;

        let data_dir = TestDataDir::new()?;
        drop(data_dir.store()?);
        let untrusted = data_dir.put_untrusted_authority_directory()?;
        // A loopback authority that refuses connections keeps the enrollment local.
        let token = Token::parse(&format!(
            "dvaet1.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"u":"https://127.0.0.1:9"}"#),
            "A".repeat(43)
        ))?;
        pending::write(&data_dir.0, &token, true)?;
        let in_progress = pending::in_progress_path(&data_dir.0, &token.sha256_hex())?;
        let (shutdown_handle, shutdown) = devolutions_gateway_task::ShutdownHandle::new();
        let task = tokio::spawn({
            let conf = test_conf()?;
            let data_dir = data_dir.0.clone();
            async move { run_identity(&conf, data_dir, &RecordingSink::default(), shutdown).await }
        });

        sleep(Duration::from_millis(500)).await;
        let processed_while_untrusted = in_progress.exists();
        std::fs::remove_dir(&untrusted)?;
        let resumed = tokio::time::timeout(Duration::from_secs(10), async {
            while !in_progress.exists() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        shutdown_handle.signal();
        task.await??;

        assert!(
            !processed_while_untrusted,
            "a pending file was processed while an authority directory was untrusted"
        );
        resumed.context("pending enrollment did not resume once the authority directory was fixed")?;
        Ok(())
    }

    #[rstest::rstest]
    #[case::authority_directory(TestDataDir::put_untrusted_authority_directory)]
    #[case::identity_file(TestDataDir::put_untrusted_identity_file)]
    #[tokio::test]
    async fn pending_poll_stops_identity_processing_once_a_stored_identity_fails_the_check(
        #[case] put_untrusted: fn(&TestDataDir) -> anyhow::Result<Utf8PathBuf>,
    ) -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity/INTENT.md §Local state
        // A stored identity that fails the check after start-up stops all identity processing too; the caller then
        // stops every runner and its streams.
        let data_dir = TestDataDir::new()?;
        let conf = test_conf()?;
        let settings = conf.debug.identity.clone().unwrap_or_default();
        let shared = Arc::new(Shared {
            store: data_dir.store()?,
            client: Client::new(conf.proxy.to_proxy_config(), None)?,
            channels: channel_client(&conf, &settings)?,
            settings,
        });
        let (_shutdown_handle, mut shutdown) = devolutions_gateway_task::ShutdownHandle::new();
        let mut runners = Runners::new(Arc::clone(&shared), shutdown.clone());
        put_untrusted(&data_dir)?;

        let stopped = tokio::time::timeout(
            Duration::from_secs(10),
            run_pending_enrollments(
                &shared,
                &mut runners,
                &data_dir.0,
                Duration::from_millis(10),
                &mut shutdown,
            ),
        )
        .await
        .context("pending poll kept running")?;

        assert!(matches!(stopped, Stopped::Untrusted));
        Ok(())
    }

    #[test]
    fn the_n_th_consecutive_failure_waits_2_to_the_n_seconds_times_jitter_then_at_most_the_maximum() {
        // oracle: intent crates/agent-identity/INTENT.md §Schedules
        // A transient failure is retried after `2^n` seconds for the `n`-th consecutive failure, multiplied by a jitter
        // from `[0.5, 1.5]`, and never longer than 1 h.
        let hour = Duration::from_secs(3600);
        assert_eq!(backoff(1, 1.0, hour), Duration::from_secs(2));
        assert_eq!(backoff(3, 1.5, hour), Duration::from_secs(12));
        assert_eq!(backoff(12, 0.5, hour), Duration::from_secs(2048));
        assert_eq!(backoff(13, 0.5, hour), hour);
        assert_eq!(backoff(40, 1.5, hour), hour);
    }

    #[test]
    fn retry_after_is_capped_by_maximum_backoff() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        // The agent waits at least `Retry-After`, up to its maximum retry delay, which
        // `crates/agent-identity/INTENT.md` ("Schedules") sets to 1 h and `backoff_max_secs` lowers
        // (`devolutions-agent/src/identity/INTENT.md`, "Configuration").
        let maximum = Duration::from_secs(17);
        assert_eq!(
            retry_delay(maximum, Duration::from_secs(5), Some(Duration::from_secs(3600))),
            maximum
        );
        assert_eq!(
            retry_delay(maximum, Duration::from_secs(12), Some(Duration::from_secs(7))),
            Duration::from_secs(12)
        );
        assert_eq!(
            retry_delay(maximum, Duration::from_secs(5), Some(Duration::from_secs(9))),
            Duration::from_secs(9)
        );
        assert_eq!(
            retry_delay(maximum, Duration::from_secs(5), None),
            Duration::from_secs(5)
        );
    }
}
