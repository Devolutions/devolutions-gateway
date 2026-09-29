use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use agent_identity::client::{Client, ClientError, PermanentCode, TerminalCode};
use agent_identity::pending::{self, PendingRead};
use agent_identity::state::{EnrollmentDiscardReason, KeyRecord, KeySlots, Store, StoredIdentity};
use agent_identity::token::Token;
use agent_identity::{csr, metadata};
#[cfg(windows)]
use agent_identity_keys::KeyBackend;
use agent_identity_keys::{DEFAULT_KEY_NAME_PREFIX, KeyOptions};
use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_agent_shared::get_data_dir;
use devolutions_gateway_task::{ShutdownSignal, Task};
use rand::Rng as _;
use tokio::time::sleep;

use crate::config::{ConfHandle, dto};

pub struct IdentityTask {
    conf_handle: ConfHandle,
}

impl IdentityTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for IdentityTask {
    type Output = anyhow::Result<()>;
    const NAME: &'static str = "identity";

    async fn run(self, mut shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let conf = self.conf_handle.get_conf();
        let settings = conf.debug.identity.clone().unwrap_or_default();
        let data_dir = get_data_dir();
        let poll_interval = Duration::from_millis(settings.pending_poll_interval_ms.unwrap_or(5_000).max(1));
        let mut last_store_error = None;
        let mut last_trust_error = None;

        loop {
            let backend = match conf.identity.key_backend {
                dto::IdentityKeyBackend::File => Store::file_backend(&data_dir),
                dto::IdentityKeyBackend::KeyStore => {
                    #[cfg(windows)]
                    {
                        KeyBackend::KeyStore
                    }
                    #[cfg(not(windows))]
                    anyhow::bail!("identity key-store backend is only available on Windows")
                }
            };
            let store = Store::new(
                data_dir.clone(),
                backend,
                settings
                    .key_name_prefix
                    .clone()
                    .unwrap_or_else(|| DEFAULT_KEY_NAME_PREFIX.to_owned()),
                KeyOptions {
                    acl_grant_current_user: settings.acl_grant_current_user.unwrap_or_default(),
                },
            )
            .context("initialize Agent Identity store")
            .and_then(|store| {
                store.reconcile().context("reconcile Agent Identity store")?;
                Ok(store)
            });
            let store = match store {
                Ok(store) => store,
                Err(error) => {
                    if log_is_due(&mut last_store_error) {
                        error!(
                            error = format!("{error:#}"),
                            directory = %data_dir.join("identity"),
                            "Agent Identity state is unavailable; fix the identity directory ownership and ACL for the service account"
                        );
                    }
                    if wait_or_stop(&mut shutdown, poll_interval).await {
                        return Ok(());
                    }
                    continue;
                }
            };
            let client = match Client::new(settings.extra_trusted_root.as_deref()) {
                Ok(client) => client,
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

            // A per-authority runner can share this reconciled store and client with pending enrollment.
            return run_pending_enrollments(&store, &client, &data_dir, &settings, poll_interval, &mut shutdown).await;
        }
    }
}

fn log_is_due(last: &mut Option<Instant>) -> bool {
    if last.is_some_and(|last| last.elapsed() < Duration::from_secs(60)) {
        false
    } else {
        *last = Some(Instant::now());
        true
    }
}

async fn wait_or_stop(shutdown: &mut ShutdownSignal, duration: Duration) -> bool {
    tokio::select! {
        _ = shutdown.wait() => true,
        _ = sleep(duration) => false,
    }
}

enum PendingOutcome {
    Completed,
    Retry {
        retry_after: Option<Duration>,
        decryption_failure: bool,
    },
}

#[derive(Default)]
struct RetryState {
    failures: u32,
    next_attempt: Option<Instant>,
    decryption_failure_since: Option<Instant>,
    last_decryption_error: Option<Instant>,
}

impl RetryState {
    fn is_due(&self) -> bool {
        self.next_attempt.is_none_or(|next| Instant::now() >= next)
    }

    fn failed(&mut self, retry_after: Option<Duration>, decryption_failure: bool, settings: &dto::IdentityDebugConf) {
        let now = Instant::now();
        if decryption_failure {
            let since = *self.decryption_failure_since.get_or_insert(now);
            if now.duration_since(since) >= Duration::from_secs(24 * 3600)
                && self
                    .last_decryption_error
                    .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(24 * 3600))
            {
                error!(
                    "Agent Identity pending enrollment has failed DPAPI decryption for 24 hours; check machine data protection"
                );
                self.last_decryption_error = Some(now);
            }
        } else {
            self.decryption_failure_since = None;
            self.last_decryption_error = None;
        }

        let max_backoff = Duration::from_secs(settings.backoff_max_secs.unwrap_or(3600).max(1));
        let exponential = Duration::from_secs((1u64 << self.failures.min(31)).min(max_backoff.as_secs()));
        let backoff = if settings.disable_jitter.unwrap_or_default() {
            exponential
        } else {
            exponential
                .mul_f64(rand::thread_rng().gen_range(0.5..=1.5))
                .min(max_backoff)
        };
        let delay = backoff.max(retry_after.unwrap_or_default());
        self.next_attempt = now.checked_add(delay).or_else(|| now.checked_add(max_backoff));
        self.failures = self.failures.saturating_add(1);
    }
}

async fn run_pending_enrollments(
    store: &Store,
    client: &Client,
    data_dir: &Utf8Path,
    settings: &dto::IdentityDebugConf,
    poll_interval: Duration,
    shutdown: &mut ShutdownSignal,
) -> anyhow::Result<()> {
    let mut retries: HashMap<Utf8PathBuf, RetryState> = HashMap::new();
    let mut last_list_error = None;
    loop {
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
                        _ = shutdown.wait() => return Ok(()),
                    };
                    match outcome {
                        Ok(PendingOutcome::Completed) => {
                            retries.remove(&path);
                        }
                        Ok(PendingOutcome::Retry {
                            retry_after,
                            decryption_failure,
                        }) => {
                            retries
                                .entry(path)
                                .or_default()
                                .failed(retry_after, decryption_failure, settings);
                        }
                        Err(error) => {
                            warn!(
                                error = format!("{error:#}"),
                                "Cannot process Agent Identity pending enrollment"
                            );
                            retries.entry(path).or_default().failed(None, false, settings);
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
            return Ok(());
        }
    }
}

async fn process_pending(
    store: &Store,
    client: &Client,
    path: &Utf8Path,
    settings: &dto::IdentityDebugConf,
) -> anyhow::Result<PendingOutcome> {
    let token = match pending::read(path, settings.acl_grant_current_user.unwrap_or_default()) {
        Ok(PendingRead::Ready(token)) => token,
        Ok(PendingRead::Malformed(_)) => {
            store.discard_pending_file(path)?;
            return Ok(PendingOutcome::Completed);
        }
        Err(error) if is_decryption_failure(&error) => {
            return Ok(PendingOutcome::Retry {
                retry_after: None,
                decryption_failure: true,
            });
        }
        Err(error) => return Err(error),
    };
    match enroll_pending(store, client, &token, settings).await {
        Err(error) if is_decryption_failure(&error) => Ok(PendingOutcome::Retry {
            retry_after: None,
            decryption_failure: true,
        }),
        outcome => outcome,
    }
}

#[cfg(windows)]
fn is_decryption_failure(error: &anyhow::Error) -> bool {
    error.downcast_ref::<pending::PendingDecryptionFailure>().is_some()
}

#[cfg(not(windows))]
fn is_decryption_failure(_error: &anyhow::Error) -> bool {
    false
}

async fn enroll_pending(
    store: &Store,
    client: &Client,
    token: &Token,
    settings: &dto::IdentityDebugConf,
) -> anyhow::Result<PendingOutcome> {
    let Some((record, key)) = store.begin_enrollment(token)? else {
        return Ok(PendingOutcome::Completed);
    };
    let csr_der = csr::create(key.as_ref()).context("create enrollment CSR")?;
    let metadata = metadata::collect(env!("CARGO_PKG_VERSION"), settings.metadata_override_path.as_deref());
    let hash = token.sha256_hex();
    match client.enroll(token, &csr_der, &metadata, key.as_ref()).await {
        Ok(response) => {
            let identity = StoredIdentity {
                version: 1,
                authority_id: response.authority_id,
                device_id: response.device_id,
                base_url: token.base_url().clone(),
                config: response.config,
                token_sha256: token.sha256_base64url(),
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
            if let Some(previous) = store.read_identity(identity.authority_id)? {
                store.replace_identity(&previous, &identity)?;
            } else {
                store.write_identity(&identity)?;
            }
            store.finish_enrollment(&hash, identity.authority_id)?;
            info!(authority_id = %identity.authority_id, device_id = %identity.device_id, "Agent Identity enrolled");
            Ok(PendingOutcome::Completed)
        }
        Err(ClientError::Permanent(code)) => {
            let reason = match code {
                PermanentCode::TokenInvalid => EnrollmentDiscardReason::TokenInvalid,
                PermanentCode::TokenExhausted => EnrollmentDiscardReason::TokenExhausted,
                PermanentCode::TokenExpired => EnrollmentDiscardReason::TokenExpired,
            };
            store.discard_enrollment(&hash, reason)?;
            warn!(
                reason = code.as_str(),
                "Discarded permanently rejected Agent Identity enrollment"
            );
            Ok(PendingOutcome::Completed)
        }
        Err(ClientError::Terminal(TerminalCode::DeviceRevoked)) => {
            store.discard_enrollment(&hash, EnrollmentDiscardReason::DeviceRevoked)?;
            warn!("Discarded revoked Agent Identity enrollment");
            Ok(PendingOutcome::Completed)
        }
        Err(error) => {
            warn!(reason = %error, "Agent Identity enrollment will retry");
            Ok(PendingOutcome::Retry {
                retry_after: error.retry_after(),
                decryption_failure: false,
            })
        }
    }
}
