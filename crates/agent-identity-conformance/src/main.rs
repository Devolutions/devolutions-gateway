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
    run: TestFn,
}

impl Test {
    const fn protocol(name: &'static str, mock_only: bool, run: TestFn) -> Self {
        Self {
            name,
            kind: Kind::Protocol,
            mock_only,
            needs_second: false,
            run,
        }
    }

    const fn agent(name: &'static str, mock_only: bool, run: TestFn) -> Self {
        Self {
            name,
            kind: Kind::Agent,
            mock_only,
            needs_second: false,
            run,
        }
    }

    const fn second(mut self) -> Self {
        self.needs_second = true;
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
    agent_bin: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    second_base_url: Option<String>,
    second_admin_token: Option<String>,
    second_ca_path: Option<PathBuf>,
    unprivileged_admin_token: Option<String>,
    key_backend: KeyBackend,
    work_dir: PathBuf,
    filter: String,
    list: bool,
    disposable_dvls_target: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            target: None,
            base_url: None,
            admin_token: None,
            agent_bin: None,
            ca_path: None,
            second_base_url: None,
            second_admin_token: None,
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
                "--agent-bin" => options.agent_bin = Some(value.into()),
                "--extra-trusted-root" => options.ca_path = Some(value.into()),
                "--second-base-url" => options.second_base_url = Some(value),
                "--second-admin-token" => options.second_admin_token = Some(value),
                "--second-extra-trusted-root" => options.second_ca_path = Some(value.into()),
                "--unprivileged-admin-token" => options.unprivileged_admin_token = Some(value),
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
        )?;
        let unprivileged_admin_token = if kind == TargetKind::Mock {
            Some(format!("{}-unprivileged", target.admin_token))
        } else {
            self.unprivileged_admin_token
        };
        let second = match (self.second_base_url, self.second_admin_token) {
            (Some(url), Some(token)) => Some(Target::new(url, token, self.second_ca_path.as_deref())?),
            (None, None) => None,
            _ => anyhow::bail!("second base URL and admin token must be supplied together"),
        };
        tokio::fs::create_dir_all(&self.work_dir).await?;
        Ok(Context {
            target,
            second,
            target_kind: kind,
            disposable_dvls_target: self.disposable_dvls_target,
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
    let context = options.context().await?;
    let start = Instant::now();
    let mut pass = 0;
    let mut fail = 0;
    let mut skip = 0;
    for test in selected {
        let test_start = Instant::now();
        if context.target_kind == TargetKind::Dvls
            && !context.disposable_dvls_target
            && (test.name.starts_with("p_rotation_") || test.name.starts_with("a_rotation_"))
        {
            println!("SKIP {} (0 ms): rotation requires --disposable-dvls-target", test.name);
            skip += 1;
            continue;
        }
        if test.name == "p_admin_permission_denied" && context.unprivileged_admin_token.is_none() {
            println!("SKIP {} (0 ms): requires --unprivileged-admin-token", test.name);
            skip += 1;
            continue;
        }
        if (test.mock_only && !context.mock())
            || (test.needs_second && context.second.is_none())
            || (test.name == "a_key_non_exportable" && (!cfg!(windows) || context.key_backend != KeyBackend::KeyStore))
            || (test.name == "a_file_backend_permissions" && (!cfg!(unix) || context.key_backend != KeyBackend::File))
        {
            println!("SKIP {} (0 ms)", test.name);
            skip += 1;
            continue;
        }
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
        let timeout = if test.kind == Kind::Protocol && test.name == "p_channel_no_hello_timeout" {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(90)
        };
        match tokio::time::timeout(timeout, result).await {
            Ok(Ok(())) => {
                println!("PASS {} ({} ms)", test.name, test_start.elapsed().as_millis());
                pass += 1;
            }
            Ok(Err(error)) => {
                println!(
                    "FAIL {} ({} ms): {error:#}",
                    test.name,
                    test_start.elapsed().as_millis()
                );
                fail += 1;
            }
            Err(_) => {
                println!(
                    "FAIL {} ({} ms): timed out",
                    test.name,
                    test_start.elapsed().as_millis()
                );
                fail += 1;
            }
        }
    }
    println!(
        "SUMMARY PASS {pass} FAIL {fail} SKIP {skip} ({} ms)",
        start.elapsed().as_millis()
    );
    if fail != 0 {
        std::process::exit(1);
    }
    Ok(())
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
    p!(p_token_n_uses_consumed_then_exhausted),
    p!(p_token_concurrent_enrollment_respects_max_uses),
    p!(p_failed_enrollment_consumes_nothing),
    p!(p_token_errors_distinct),
    p!(p_token_expired, mock_only),
    p!(p_enroll_idempotent_same_key),
    p!(p_enroll_revoked_same_key_rejected),
    p!(p_metadata_limits),
    p!(p_friendly_name_format),
    p!(p_device_cannot_impersonate_another),
    p!(p_replay_nonce_rejected),
    p!(p_replay_window_rejected),
    p!(p_connect_signature_replayed_to_renew),
    p!(p_renew_happy_path),
    p!(p_renew_idempotent_lost_response, mock_only),
    p!(p_renew_second_pending_retires_first),
    p!(p_renew_within_grace, mock_only),
    p!(p_renew_beyond_grace, mock_only),
    p!(p_revocation_blocks_renew_and_connect),
    p!(p_delete_only_when_revoked_then_unknown),
    p!(p_channel_hello_updates_metadata_and_connected),
    p!(p_channel_proof_replay_fails),
    p!(p_channel_no_hello_timeout),
    p!(p_channel_unavailable_no_channel_url, mock_only),
    p!(p_request_renewal_connected_and_on_connect),
    p!(p_request_renewal_flag_cleared_after_new_cert),
    p!(p_reconnect_push_and_handoff, mock_only),
    p!(p_revocation_closes_stream),
    p!(p_stream_closes_at_not_after, mock_only),
    p!(p_pending_cert_auth_retires_old_and_closes_streams),
    p!(p_rotation_publishes_both_roots_and_issues_from_new),
    p!(p_rotation_status_counts),
    p!(p_rotation_conflict_409),
    p!(p_rotation_deadline_removes_old_root, mock_only),
    p!(p_rotation_old_root_cert_renewable_after_deadline, mock_only),
    p!(p_rotation_emergency_deadline, mock_only),
    p!(p_rotation_request_renewal_pushed),
    p!(p_listing_pagination_stable_during_concurrent_enrollment),
    p!(p_listing_views_filters_and_bounds),
    p!(p_admin_tokens_crud_and_states),
    p!(p_admin_requires_auth),
    p!(p_admin_permission_denied),
    p!(p_error_body_shape),
    a!(a_pending_file_enroll_success),
    a!(a_pending_file_deleted_on_permanent_error),
    a!(a_pending_file_kept_on_transient_error),
    a!(a_token_never_logged),
    a!(a_same_token_no_enrollment),
    a!(a_same_token_rejected_identity_no_enrollment),
    a!(a_different_token_replaces_identity),
    a!(a_cli_identity_enroll_writes_pending_file),
    a!(a_renewal_happy_path),
    a!(a_renewal_lost_response_retried, mock_only),
    a!(a_channel_connected_and_metadata),
    a!(a_make_before_break_on_renewal),
    a!(a_request_renewal_connected),
    a!(a_request_renewal_while_offline),
    a!(a_reconnect_make_before_break, mock_only),
    a!(a_revocation_stops_agent),
    a!(a_device_unknown_recorded, mock_only),
    a!(a_no_channel_when_absent, mock_only),
    a!(a_multi_authority).second(),
    a!(a_key_non_exportable),
    a!(a_file_backend_permissions),
    a!(a_rotation_migrates_connected_agent),
    a!(a_rotation_migrates_on_schedule, mock_only),
];
