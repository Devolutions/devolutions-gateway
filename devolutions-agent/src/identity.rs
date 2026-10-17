use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use agent_identity::client::{Client, ClientError, PermanentCode, TerminalCode};
use agent_identity::pending::{self, PendingRead};
use agent_identity::state::{EnrollmentDiscardReason, KeyRecord, KeySlots, PendingDiscard, Store, StoredIdentity};
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
            let client = match Client::new(conf.proxy.to_proxy_config(), settings.extra_trusted_root.as_deref()) {
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

    fn failed(&mut self, settings: &dto::IdentityDebugConf, retry_after: Option<Duration>) {
        let now = Instant::now();
        let max_backoff = Duration::from_secs(settings.backoff_max_secs.unwrap_or(3600).max(1));
        let exponential = Duration::from_secs((1u64 << self.failures.min(31)).min(max_backoff.as_secs()));
        let backoff = if settings.disable_jitter.unwrap_or_default() {
            exponential
        } else {
            exponential
                .mul_f64(rand::thread_rng().gen_range(0.5..=1.5))
                .min(max_backoff)
        };
        let delay = retry_delay(max_backoff, backoff, retry_after);
        self.next_attempt = now.checked_add(delay).or_else(|| now.checked_add(max_backoff));
        self.failures = self.failures.saturating_add(1);
    }
}

fn retry_delay(maximum: Duration, backoff: Duration, retry_after: Option<Duration>) -> Duration {
    backoff.max(retry_after.unwrap_or_default()).min(maximum)
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
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_capped_by_maximum_backoff() {
        // `CONTRACT.md` §5.4 and `identity.intent.md` ("Configuration") cap `Retry-After` at the maximum backoff.
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
