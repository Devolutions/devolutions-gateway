#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the conformance runner reports every test and its summary to the CLI"
)]

mod agent;
mod channel;
mod client;
mod protocol;
mod signer;
#[cfg(windows)]
mod windows;

use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};

use crate::client::Target;

type TestFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type TestFn = fn(Context) -> TestFuture;
const RUN_DEADLINE: Duration = Duration::from_secs(13 * 60);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Protocol,
    Agent,
}

struct Test {
    name: &'static str,
    kind: Kind,
    mock_only: bool,
    needs_second: bool,
    needs_channel: bool,
    run: TestFn,
}

impl Test {
    const fn protocol(name: &'static str, mock_only: bool, run: TestFn) -> Self {
        Self {
            name,
            kind: Kind::Protocol,
            mock_only,
            needs_second: false,
            needs_channel: false,
            run,
        }
    }

    const fn agent(name: &'static str, mock_only: bool, run: TestFn) -> Self {
        Self {
            name,
            kind: Kind::Agent,
            mock_only,
            needs_second: false,
            needs_channel: false,
            run,
        }
    }

    const fn second(mut self) -> Self {
        self.needs_second = true;
        self
    }

    const fn channel(mut self) -> Self {
        self.needs_channel = true;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Mock,
    Dvls,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyBackend {
    KeyStore,
    File,
}

impl KeyBackend {
    const fn name(self) -> &'static str {
        match self {
            Self::KeyStore => "KeyStore",
            Self::File => "File",
        }
    }
}

#[derive(Clone)]
struct Context {
    target: Target,
    second: Option<Target>,
    target_kind: TargetKind,
    disposable_dvls_target: bool,
    dvls_rotation_window_secs: u64,
    leaf_lifetime_secs: u64,
    expect_channel: bool,
    channel_available: bool,
    key_name_prefix: String,
    agent_version: Option<String>,
    unprivileged_admin_token: Option<String>,
    agent_bin: PathBuf,
    key_backend: KeyBackend,
    work_dir: PathBuf,
}

impl Context {
    fn mock(&self) -> bool {
        self.target_kind == TargetKind::Mock
    }
}

struct Options {
    target: Option<TargetKind>,
    base_url: Option<String>,
    admin_token: Option<String>,
    authority_id: Option<String>,
    agent_bin: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    second_base_url: Option<String>,
    second_admin_token: Option<String>,
    second_authority_id: Option<String>,
    second_ca_path: Option<PathBuf>,
    unprivileged_admin_token: Option<String>,
    key_backend: KeyBackend,
    work_dir: PathBuf,
    filter: String,
    list: bool,
    disposable_dvls_target: bool,
    dvls_rotation_window_secs: u64,
    leaf_lifetime_secs: u64,
    expect_channel: bool,
    allow_incomplete: bool,
    agent_version: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            target: None,
            base_url: None,
            admin_token: None,
            authority_id: None,
            agent_bin: None,
            ca_path: None,
            second_base_url: None,
            second_admin_token: None,
            second_authority_id: None,
            second_ca_path: None,
            unprivileged_admin_token: None,
            key_backend: if cfg!(windows) {
                KeyBackend::KeyStore
            } else {
                KeyBackend::File
            },
            work_dir: PathBuf::from("target").join("agent-identity-conformance"),
            filter: String::new(),
            list: false,
            disposable_dvls_target: false,
            dvls_rotation_window_secs: 60,
            leaf_lifetime_secs: 90 * 24 * 3600,
            expect_channel: true,
            allow_incomplete: false,
            agent_version: None,
        }
    }
}

impl Options {
    fn parse() -> anyhow::Result<Self> {
        let mut options = Self::default();
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--list" {
                options.list = true;
                continue;
            }
            if flag == "--disposable-dvls-target" {
                options.disposable_dvls_target = true;
                continue;
            }
            if flag == "--allow-incomplete" {
                options.allow_incomplete = true;
                continue;
            }
            if flag == "--no-expect-channel" {
                options.expect_channel = false;
                continue;
            }
            let value = args.next().with_context(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--target" => {
                    options.target = Some(match value.as_str() {
                        "mock" => TargetKind::Mock,
                        "dvls" => TargetKind::Dvls,
                        _ => anyhow::bail!("unknown target"),
                    });
                }
                "--base-url" => options.base_url = Some(value),
                "--admin-token" => options.admin_token = Some(value),
                "--authority-id" => options.authority_id = Some(value),
                "--agent-bin" => options.agent_bin = Some(value.into()),
                "--agent-version" => {
                    ensure!(!value.is_empty(), "--agent-version must not be empty");
                    options.agent_version = Some(value);
                }
                "--extra-trusted-root" => options.ca_path = Some(value.into()),
                "--second-base-url" => options.second_base_url = Some(value),
                "--second-admin-token" => options.second_admin_token = Some(value),
                "--second-authority-id" => options.second_authority_id = Some(value),
                "--second-extra-trusted-root" => options.second_ca_path = Some(value.into()),
                "--unprivileged-admin-token" => options.unprivileged_admin_token = Some(value),
                "--expect-channel" => {
                    options.expect_channel = value.parse().context("--expect-channel must be true or false")?
                }
                "--leaf-lifetime-secs" => {
                    options.leaf_lifetime_secs = value
                        .parse()
                        .context("--leaf-lifetime-secs must be a positive integer")?;
                    ensure!(options.leaf_lifetime_secs > 0, "--leaf-lifetime-secs must be positive");
                }
                "--dvls-rotation-window-secs" => {
                    options.dvls_rotation_window_secs = value
                        .parse()
                        .context("--dvls-rotation-window-secs must be a positive integer")?;
                    ensure!(
                        options.dvls_rotation_window_secs > 0,
                        "--dvls-rotation-window-secs must be positive"
                    );
                }
                "--key-backend" => {
                    options.key_backend = match value.as_str() {
                        "key-store" => KeyBackend::KeyStore,
                        "file" => KeyBackend::File,
                        _ => anyhow::bail!("unknown key backend"),
                    };
                }
                "--work-dir" => options.work_dir = value.into(),
                "--filter" => options.filter = value,
                _ => anyhow::bail!("unknown flag {flag}"),
            }
        }
        Ok(options)
    }

    async fn context(self) -> anyhow::Result<Context> {
        let kind = self.target.context("--target is required")?;
        let target = Target::new(
            self.base_url.context("--base-url is required")?,
            self.admin_token.context("--admin-token is required")?,
            self.ca_path.as_deref(),
            self.authority_id.as_deref(),
        )?;
        let unprivileged_admin_token = if kind == TargetKind::Mock {
            Some(format!("{}-unprivileged", target.admin_token))
        } else {
            self.unprivileged_admin_token
        };
        let second = match (self.second_base_url, self.second_admin_token) {
            (Some(url), Some(token)) => Some(Target::new(
                url,
                token,
                self.second_ca_path.as_deref(),
                self.second_authority_id.as_deref(),
            )?),
            (None, None) => None,
            _ => anyhow::bail!("second base URL and admin token must be supplied together"),
        };
        ensure!(
            second.is_some() || self.second_authority_id.is_none(),
            "--second-authority-id requires a second target"
        );
        if kind == TargetKind::Mock {
            target.reset().await?;
            if let Some(other) = &second {
                other.reset().await?;
            }
        }
        let channel_available = if self.expect_channel {
            true
        } else {
            target.channel_available().await?
        };
        tokio::fs::create_dir_all(&self.work_dir).await?;
        Ok(Context {
            target,
            second,
            target_kind: kind,
            disposable_dvls_target: self.disposable_dvls_target,
            dvls_rotation_window_secs: self.dvls_rotation_window_secs,
            leaf_lifetime_secs: self.leaf_lifetime_secs,
            expect_channel: self.expect_channel,
            channel_available,
            key_name_prefix: format!("DevolutionsAgent-Identity-conformance-{}-", uuid::Uuid::new_v4()),
            agent_version: self.agent_version,
            unprivileged_admin_token,
            agent_bin: self.agent_bin.context("--agent-bin is required")?,
            key_backend: self.key_backend,
            work_dir: self.work_dir,
        })
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("conformance runner error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let options = Options::parse()?;
    let selected: Vec<&Test> = TESTS
        .iter()
        .filter(|test| test.name.contains(&options.filter))
        .collect();
    if options.list {
        for test in selected {
            println!("{}", test.name);
        }
        return Ok(());
    }
    ensure!(!selected.is_empty(), "no tests match the filter");
    let allow_incomplete = options.allow_incomplete;
    let start = Instant::now();
    let deadline = start + RUN_DEADLINE;
    let context = tokio::time::timeout(RUN_DEADLINE, options.context())
        .await
        .context("conformance setup exceeded the 13-minute deadline")??;
    println!("KEY NAME PREFIX {}", context.key_name_prefix);
    let mut totals = [0u32; 4];
    let mut protocol_elapsed = Duration::ZERO;
    let mut agent_elapsed = Duration::ZERO;
    let mut non_pass = Vec::new();
    let mut deadline_exceeded = false;
    for test in selected {
        let test_start = Instant::now();
        let outcome = if test.mock_only && !context.mock() {
            Outcome::NotApplicable("requires the mock-only control API")
        } else if test.name == "a_key_non_exportable" && !cfg!(windows) {
            Outcome::NotApplicable("Windows key-store test")
        } else if test.name == "a_file_backend_permissions" && !cfg!(unix) {
            Outcome::NotApplicable("Unix file-backend test")
        } else if test.needs_channel && !context.expect_channel && !context.channel_available {
            Outcome::NotApplicable("config.agent_channel_url absent and --expect-channel=false")
        } else if context.target_kind == TargetKind::Dvls
            && !context.disposable_dvls_target
            && (test.name.starts_with("p_rotation_") || test.name.starts_with("a_rotation_"))
        {
            Outcome::Skip("rotation requires --disposable-dvls-target")
        } else if test.name == "p_stream_closes_at_not_after" && !context.mock() && context.leaf_lifetime_secs > 30 {
            Outcome::Skip("real-target stream expiry requires --leaf-lifetime-secs <= 30")
        } else if test.name == "p_admin_permission_denied" && context.unprivileged_admin_token.is_none() {
            Outcome::Skip("requires --unprivileged-admin-token")
        } else if test.needs_second && context.second.is_none() {
            Outcome::Skip("requires a second authority (--second-base-url and --second-admin-token)")
        } else if test.name == "a_key_non_exportable" && context.key_backend != KeyBackend::KeyStore {
            Outcome::Skip("requires --key-backend key-store")
        } else if test.name == "a_file_backend_permissions" && context.key_backend != KeyBackend::File {
            Outcome::Skip("requires --key-backend file")
        } else {
            let result = async {
                if context.mock() {
                    context.target.reset().await?;
                    if test.needs_second {
                        context
                            .second
                            .as_ref()
                            .context("missing second target")?
                            .reset()
                            .await?;
                    }
                }
                (test.run)(context.clone()).await
            };
            let timeout = if test.name == "p_channel_no_hello_timeout" {
                Duration::from_secs(20)
            } else if !context.mock() && test.name.starts_with("a_rotation_") {
                Duration::from_secs(context.dvls_rotation_window_secs.saturating_add(60))
            } else if !context.mock() && test.name.starts_with("p_rotation_") {
                Duration::from_secs(context.dvls_rotation_window_secs.saturating_add(30))
            } else {
                Duration::from_secs(90)
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let allowed = timeout.min(remaining);
            match tokio::time::timeout(allowed, result).await {
                Ok(Ok(())) => Outcome::Pass,
                Ok(Err(error)) => Outcome::Fail(format!("{error:#}")),
                Err(_) if allowed == remaining => {
                    deadline_exceeded = true;
                    Outcome::Fail("global 13-minute deadline exceeded".to_owned())
                }
                Err(_) => Outcome::Fail("timed out".to_owned()),
            }
        };
        let elapsed = test_start.elapsed();
        match test.kind {
            Kind::Protocol => protocol_elapsed += elapsed,
            Kind::Agent => agent_elapsed += elapsed,
        }
        let (index, label, reason) = match outcome {
            Outcome::Pass => (0, "PASS", None),
            Outcome::Fail(reason) => (1, "FAIL", Some(reason)),
            Outcome::Skip(reason) => (2, "SKIP", Some(reason.to_owned())),
            Outcome::NotApplicable(reason) => (3, "N/A", Some(reason.to_owned())),
        };
        totals[index] += 1;
        if let Some(reason) = reason {
            println!("{label} {} ({} ms): {reason}", test.name, elapsed.as_millis());
            non_pass.push((label, test.name, reason));
        } else {
            println!("{label} {} ({} ms)", test.name, elapsed.as_millis());
        }
        if deadline_exceeded {
            break;
        }
    }
    println!(
        "SUMMARY PASS {} FAIL {} SKIP {} N/A {} ({} ms)",
        totals[0],
        totals[1],
        totals[2],
        totals[3],
        start.elapsed().as_millis()
    );
    println!(
        "SUMMARY DURATION protocol={} ms agent={} ms",
        protocol_elapsed.as_millis(),
        agent_elapsed.as_millis()
    );
    for (label, name, reason) in non_pass {
        println!("NON-PASS {label} {name}: {reason}");
    }
    if totals[1] != 0 || (totals[2] != 0 && !allow_incomplete) {
        anyhow::bail!(
            "conformance failed: {} failures, {} incomplete skips{}",
            totals[1],
            totals[2],
            if allow_incomplete { " (allowed)" } else { "" }
        );
    }
    Ok(())
}

enum Outcome {
    Pass,
    Fail(String),
    Skip(&'static str),
    NotApplicable(&'static str),
}

macro_rules! p {
    ($name:ident) => {
        Test::protocol(stringify!($name), false, |context| Box::pin(protocol::$name(context)))
    };
    ($name:ident, mock_only) => {
        Test::protocol(stringify!($name), true, |context| Box::pin(protocol::$name(context)))
    };
}

macro_rules! a {
    ($name:ident) => {
        Test::agent(stringify!($name), false, |context| Box::pin(agent::$name(context)))
    };
    ($name:ident, mock_only) => {
        Test::agent(stringify!($name), true, |context| Box::pin(agent::$name(context)))
    };
}

const TESTS: &[Test] = &[
    p!(p_trust_anchor_lists_roots),
    p!(p_channel_url_expectation),
    p!(p_reset_rebases_root_validity, mock_only),
    p!(p_token_n_uses_consumed_then_exhausted),
    p!(p_token_concurrent_enrollment_respects_max_uses),
    p!(p_concurrent_same_key_enroll_replays_winner),
    p!(p_concurrent_same_key_renew_replays_winner),
    p!(p_failed_enrollment_consumes_nothing),
    p!(p_token_errors_distinct),
    p!(p_token_expired, mock_only),
    p!(p_enroll_idempotent_same_key),
    p!(p_deleted_token_replays_own_key_only),
    p!(p_enroll_revoked_same_key_rejected),
    p!(p_enroll_certificate_key_reuse_rules),
    p!(p_renew_certificate_key_reuse_rules),
    p!(p_metadata_limits),
    p!(p_friendly_name_format),
    p!(p_device_cannot_impersonate_another),
    p!(p_channel_hello_cannot_impersonate_another).channel(),
    p!(p_renew_digest_integrity),
    p!(p_renew_rejects_sha384_csr),
    p!(p_signature_parser_wire_negatives),
    p!(p_replay_nonce_rejected),
    p!(p_replay_window_rejected),
    p!(p_connect_signature_replayed_to_renew),
    p!(p_renew_signature_rejected_on_connect).channel(),
    p!(p_channel_duplicate_signature_metadata_rejected).channel(),
    p!(p_confirm_cross_tag_signatures_rejected).channel(),
    p!(p_check_in_current_and_pending),
    p!(p_check_in_cross_tag_signatures_rejected),
    p!(p_check_in_signature_rejected_on_connect).channel(),
    p!(p_renew_happy_path),
    p!(p_confirm_promotes_and_is_idempotent),
    p!(p_confirm_retired_certificate_rejected),
    p!(p_confirm_expired_pending_certificate_rejected, mock_only),
    p!(p_confirm_nonempty_body_rejected),
    p!(p_confirm_faults_do_not_duplicate_promotion, mock_only),
    p!(p_renew_idempotent_lost_response, mock_only),
    p!(p_mock_enroll_retry_barrier, mock_only),
    p!(p_renew_second_pending_retires_first),
    p!(p_retired_pending_certificate_cannot_connect).channel(),
    p!(p_renew_within_grace, mock_only),
    p!(p_renew_beyond_grace, mock_only),
    p!(p_revocation_blocks_renew_and_connect),
    p!(p_revocation_blocks_connect).channel(),
    p!(p_delete_only_when_revoked_then_unknown),
    p!(p_deleted_certificate_cannot_connect).channel(),
    p!(p_channel_hello_updates_metadata_and_connected).channel(),
    p!(p_handshake_barrier_holds_authentication, mock_only).channel(),
    p!(p_channel_proof_replay_fails).channel(),
    p!(p_channel_revoked_before_hello).channel(),
    p!(p_channel_no_hello_timeout).channel(),
    p!(p_channel_unavailable_no_channel_url, mock_only),
    p!(p_config_revision_monotonic_changes, mock_only).channel(),
    p!(p_config_hello_reconciles_stale_revision).channel(),
    p!(p_config_update_pushes_higher_revision, mock_only).channel(),
    p!(p_request_renewal_connected_and_on_connect).channel(),
    p!(p_request_renewal_flag_cleared_only_on_confirm),
    p!(p_request_renewal_flag_cleared_after_new_cert).channel(),
    p!(p_reconnect_push_and_handoff, mock_only).channel(),
    p!(p_revocation_closes_stream).channel(),
    p!(p_stream_closes_at_not_after).channel(),
    p!(p_challenged_stream_expires_on_advance, mock_only).channel(),
    p!(p_pending_cert_auth_does_not_promote).channel(),
    p!(p_confirm_reconnects_and_closes_retired_stream_at_grace, mock_only).channel(),
    p!(p_rotation_publishes_both_roots_and_issues_from_new),
    p!(p_rotation_status_counts),
    p!(p_rotation_conflict_409),
    p!(p_rotation_completes_early_when_last_device_migrates, mock_only),
    p!(p_rotation_completes_immediately_without_old_root_devices, mock_only),
    p!(p_rotation_deadline_bound, mock_only),
    p!(p_rotation_grace_renewal_after_early_completion, mock_only),
    p!(p_rotation_completes_early_at_certificate_expiry_via_freeze, mock_only),
    p!(p_rotation_push_rate_survives_deadline, mock_only).channel(),
    p!(p_rotation_deadline_removes_old_root),
    p!(p_rotation_old_root_cert_renewable_after_deadline, mock_only),
    p!(p_rotation_emergency_deadline, mock_only),
    p!(p_rotation_request_renewal_pushed).channel(),
    p!(p_rotation_pending_only_old_root_receives_push, mock_only).channel(),
    p!(p_listing_pagination_stable_during_concurrent_enrollment),
    p!(p_listing_views_filters_and_bounds),
    p!(p_admin_tokens_crud_and_states),
    p!(p_admin_requires_auth),
    p!(p_admin_permission_denied),
    p!(p_rotation_admin_write_requires_auth),
    p!(p_error_body_shape),
    p!(p_mock_fault_response_not_processed, mock_only),
    a!(a_pending_file_enroll_success),
    a!(a_enroll_lost_response_retried_across_restart, mock_only),
    a!(a_two_pending_tokens_same_authority_last_wins, mock_only),
    a!(
        a_two_pending_tokens_different_authorities_progress_independently,
        mock_only
    )
    .second(),
    a!(a_enroll_revoked_before_response_is_permanent, mock_only),
    a!(a_pending_file_deleted_on_permanent_error),
    a!(a_pending_file_kept_on_transient_error),
    a!(a_token_never_logged),
    a!(a_same_token_no_enrollment),
    a!(a_same_token_rejected_identity_no_enrollment).channel(),
    a!(a_different_token_replaces_identity),
    a!(a_rejected_identity_replaced).channel(),
    a!(a_cli_identity_enroll_writes_pending_file),
    a!(a_renewal_happy_path).channel(),
    a!(a_renewal_lost_response_retried, mock_only).channel(),
    a!(a_renewal_lost_confirm_response_retried, mock_only).channel(),
    a!(a_confirm_expired_pending_renews_with_fresh_key, mock_only),
    a!(a_expired_current_renews_in_grace_or_rejects_beyond, mock_only).channel(),
    a!(a_channel_connected_and_metadata).channel(),
    a!(a_make_before_break_on_renewal).channel(),
    a!(a_old_key_deleted_after_confirm_without_channel, mock_only).channel(),
    a!(a_request_renewal_connected).channel(),
    a!(a_request_renewal_while_offline).channel(),
    a!(a_reconnect_make_before_break, mock_only).channel(),
    a!(a_revocation_stops_agent).channel(),
    a!(a_device_unknown_recorded, mock_only).channel(),
    a!(a_signed_rejection_without_live_stream, mock_only),
    a!(a_no_channel_when_absent, mock_only),
    a!(a_config_update_disables_channel, mock_only).channel(),
    a!(a_check_in_enables_channel, mock_only),
    a!(a_check_in_recovers_broken_channel, mock_only),
    a!(a_config_unknown_fields_and_hello_revision, mock_only).channel(),
    a!(a_multi_authority).second().channel(),
    a!(a_key_non_exportable),
    a!(a_file_backend_permissions),
    a!(a_rotation_migrates_connected_agent).channel(),
    a!(a_rotation_migrates_on_schedule, mock_only),
];
