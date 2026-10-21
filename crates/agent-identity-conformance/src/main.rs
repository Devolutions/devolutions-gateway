#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the conformance runner reports every test and its summary to the CLI"
)]

mod agent;
mod authority;
mod channel;
mod client;
mod dvls;
mod protocol;
mod signer;
#[cfg(windows)]
mod system_probe;
#[cfg(windows)]
mod windows;

use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};

use crate::authority::{Authority, AuthoritySpec, Need, Profile};
use crate::client::Target;
use crate::dvls::AppCredential;

type TestFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type TestFn = fn(Context) -> TestFuture;
const RUN_DEADLINE: Duration = Duration::from_secs(14 * 60 + 30);
/// How long a test may run unless [`run_test`] gives it another timeout.
const TEST_TIMEOUT: Duration = Duration::from_secs(90);

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
    /// The [`Need::bit`] of each need, beyond rotation's, that the test has of its authority.
    needs: u8,
    /// Whether the test starts the agent, which then creates device keys.
    starts_agent: bool,
    run: TestFn,
}

impl Test {
    const fn protocol(name: &'static str, mock_only: bool, run: TestFn) -> Self {
        Self {
            name,
            kind: Kind::Protocol,
            mock_only,
            needs_second: false,
            needs: 0,
            starts_agent: false,
            run,
        }
    }

    const fn agent(name: &'static str, mock_only: bool, run: TestFn) -> Self {
        Self {
            name,
            kind: Kind::Agent,
            mock_only,
            needs_second: false,
            needs: 0,
            starts_agent: true,
            run,
        }
    }

    const fn second(mut self) -> Self {
        self.needs_second = true;
        self
    }

    const fn need(mut self, need: Need) -> Self {
        self.needs |= need.bit();
        self
    }

    const fn channel(self) -> Self {
        self.need(Need::Channel)
    }

    const fn without_channel(self) -> Self {
        self.need(Need::NoChannel)
    }

    /// Marks an agent test that only runs the agent's CLI.
    const fn cli_only(mut self) -> Self {
        self.starts_agent = false;
        self
    }

    /// What the test needs of its authority; every rotation test needs a disposable one.
    fn needs(&self) -> Vec<Need> {
        let rotation = self.name.starts_with("p_rotation_") || self.name.starts_with("a_rotation_");
        Need::ALL
            .into_iter()
            .filter(|need| self.needs & need.bit() != 0 || rotation && *need == Need::Disposable)
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Mock,
    Dvls,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyBackend {
    WindowsSoftwareProvider,
    File,
}

impl KeyBackend {
    const fn name(self) -> &'static str {
        match self {
            Self::WindowsSoftwareProvider => "WindowsSoftwareProvider",
            Self::File => "File",
        }
    }
}

/// What one test runs with: the authority it runs on, the second one when it needs two, and the run's settings.
#[derive(Clone)]
struct Context {
    /// The name of the test.
    test: &'static str,
    target: Target,
    second: Option<Authority>,
    target_kind: TargetKind,
    disposable_dvls_target: bool,
    dvls_rotation_window_secs: u64,
    leaf_lifetime_secs: u64,
    expect_channel: bool,
    channel_available: bool,
    key_name_prefix: String,
    agent_version: Option<String>,
    /// On DVLS, a session of an application identity without any Agent Identity permission.
    unprivileged: Option<Arc<dvls::Session>>,
    agent_bin: PathBuf,
    key_backend: KeyBackend,
    work_dir: PathBuf,
}

impl Context {
    fn mock(&self) -> bool {
        self.target_kind == TargetKind::Mock
    }

    fn leaf_lifetime(&self) -> Duration {
        Duration::from_secs(self.leaf_lifetime_secs)
    }
}

/// The authorities and settings of a run.
struct Suite {
    /// The authority that `--base-url` names, then the one `--second-base-url` names, then each `--authority` in order.
    authorities: Vec<Authority>,
    target_kind: TargetKind,
    key_name_prefix: String,
    agent_version: Option<String>,
    /// On DVLS, a session of an application identity without any Agent Identity permission on the first authority.
    unprivileged: Option<Arc<dvls::Session>>,
    agent_bin: PathBuf,
    key_backend: KeyBackend,
    work_dir: PathBuf,
}

impl Suite {
    fn mock(&self) -> bool {
        self.target_kind == TargetKind::Mock
    }

    /// The context of `test` on the authorities at `primary` and `second`.
    fn context(&self, test: &'static str, primary: usize, second: Option<usize>) -> Context {
        let authority = &self.authorities[primary];
        Context {
            test,
            target: authority.target.clone(),
            second: second.map(|index| self.authorities[index].clone()),
            target_kind: self.target_kind,
            disposable_dvls_target: authority.profile.disposable,
            dvls_rotation_window_secs: authority.rotation_window_secs,
            leaf_lifetime_secs: authority.profile.leaf_lifetime_secs,
            expect_channel: authority.profile.expect_channel,
            channel_available: authority.channel_available,
            key_name_prefix: self.key_name_prefix.clone(),
            agent_version: self.agent_version.clone(),
            // UNTESTED: a test that runs on another authority than the first gets no unprivileged session.
            // `--unprivileged-app-key` names an application identity of the first authority, which another authority refuses at login, so its permission tests would fail instead of skipping.
            // When changing which authority a test runs on, keep this session on the first one.
            unprivileged: if primary == 0 { self.unprivileged.clone() } else { None },
            agent_bin: self.agent_bin.clone(),
            key_backend: self.key_backend,
            work_dir: self.work_dir.clone(),
        }
    }
}

struct Options {
    target: Option<TargetKind>,
    base_url: Option<String>,
    app_key: Option<String>,
    app_secret: Option<String>,
    authority_id: Option<String>,
    agent_bin: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    second_base_url: Option<String>,
    second_app_key: Option<String>,
    second_app_secret: Option<String>,
    second_authority_id: Option<String>,
    second_ca_path: Option<PathBuf>,
    /// Each `--authority` value, as given.
    authorities: Vec<String>,
    unprivileged_app_key: Option<String>,
    unprivileged_app_secret: Option<String>,
    key_backend: KeyBackend,
    work_dir: PathBuf,
    filter: String,
    list: bool,
    disposable_dvls_target: bool,
    /// `None` derives the window from `leaf_lifetime_secs`.
    dvls_rotation_window_secs: Option<u64>,
    leaf_lifetime_secs: u64,
    expect_channel: bool,
    allow_incomplete: bool,
    agent_version: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        let profile = Profile::default();
        Self {
            target: None,
            base_url: None,
            app_key: None,
            app_secret: None,
            authority_id: None,
            agent_bin: None,
            ca_path: None,
            second_base_url: None,
            second_app_key: None,
            second_app_secret: None,
            second_authority_id: None,
            second_ca_path: None,
            authorities: Vec::new(),
            unprivileged_app_key: None,
            unprivileged_app_secret: None,
            key_backend: if cfg!(windows) {
                KeyBackend::WindowsSoftwareProvider
            } else {
                KeyBackend::File
            },
            work_dir: PathBuf::from("target").join("agent-identity-conformance"),
            filter: String::new(),
            list: false,
            disposable_dvls_target: profile.disposable,
            dvls_rotation_window_secs: profile.rotation_window_secs,
            leaf_lifetime_secs: profile.leaf_lifetime_secs,
            expect_channel: profile.expect_channel,
            allow_incomplete: false,
            agent_version: None,
        }
    }
}

impl Options {
    /// Reads the runner's arguments, without the program name.
    fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut options = Self::default();
        let mut args = args.into_iter().zip(1..);
        while let Some((flag, position)) = args.next() {
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
            // An argument that is not a known flag may be a misplaced secret, so errors name only known flags.
            let mut value = || {
                args.next()
                    .map(|(value, _)| value)
                    .with_context(|| format!("missing value for {flag}"))
            };
            match flag.as_str() {
                "--target" => {
                    options.target = Some(match value()?.as_str() {
                        "mock" => TargetKind::Mock,
                        "dvls" => TargetKind::Dvls,
                        _ => anyhow::bail!("unknown target"),
                    });
                }
                "--base-url" => options.base_url = Some(value()?),
                "--app-key" => options.app_key = Some(value()?),
                "--app-secret" => options.app_secret = Some(value()?),
                "--authority-id" => options.authority_id = Some(value()?),
                "--agent-bin" => options.agent_bin = Some(value()?.into()),
                "--agent-version" => {
                    let version = value()?;
                    ensure!(!version.is_empty(), "--agent-version must not be empty");
                    options.agent_version = Some(version);
                }
                "--extra-trusted-root" => options.ca_path = Some(value()?.into()),
                "--second-base-url" => options.second_base_url = Some(value()?),
                "--second-app-key" => options.second_app_key = Some(value()?),
                "--second-app-secret" => options.second_app_secret = Some(value()?),
                "--second-authority-id" => options.second_authority_id = Some(value()?),
                "--second-extra-trusted-root" => options.second_ca_path = Some(value()?.into()),
                "--unprivileged-app-key" => options.unprivileged_app_key = Some(value()?),
                "--unprivileged-app-secret" => options.unprivileged_app_secret = Some(value()?),
                "--expect-channel" => {
                    options.expect_channel = value()?.parse().context("--expect-channel must be true or false")?
                }
                "--leaf-lifetime-secs" => {
                    options.leaf_lifetime_secs = value()?
                        .parse()
                        .context("--leaf-lifetime-secs must be a positive integer")?;
                    ensure!(options.leaf_lifetime_secs > 0, "--leaf-lifetime-secs must be positive");
                }
                "--dvls-rotation-window-secs" => {
                    let window: u64 = value()?
                        .parse()
                        .context("--dvls-rotation-window-secs must be a positive integer")?;
                    ensure!(window > 0, "--dvls-rotation-window-secs must be positive");
                    options.dvls_rotation_window_secs = Some(window);
                }
                "--key-backend" => {
                    options.key_backend = match value()?.as_str() {
                        "windows-software-provider" => KeyBackend::WindowsSoftwareProvider,
                        "file" => KeyBackend::File,
                        _ => anyhow::bail!("unknown key backend"),
                    };
                }
                "--work-dir" => options.work_dir = value()?.into(),
                "--filter" => options.filter = value()?,
                "--authority" => options.authorities.push(value()?),
                _ => anyhow::bail!("argument {position} is not a known flag"),
            }
        }
        Ok(options)
    }

    /// The profile that the run's flags declare for the authorities `--base-url` and `--second-base-url` name.
    fn profile(&self) -> Profile {
        Profile {
            leaf_lifetime_secs: self.leaf_lifetime_secs,
            expect_channel: self.expect_channel,
            disposable: self.disposable_dvls_target,
            rotation_window_secs: self.dvls_rotation_window_secs,
        }
    }

    async fn suite(self) -> anyhow::Result<Suite> {
        let kind = self.target.context("--target is required")?;
        let profile = self.profile();
        let key_name_prefix = format!("conformance-{}", uuid::Uuid::new_v4().simple());
        #[cfg(windows)]
        if self.key_backend == KeyBackend::File {
            use std::os::windows::ffi::OsStrExt as _;

            let work_dir = std::path::absolute(&self.work_dir).context("resolve --work-dir")?;
            let length = work_dir.as_os_str().encode_wide().count();
            let longest = longest_file_backend_work_dir(&key_name_prefix);
            ensure!(
                length <= longest,
                "--work-dir must be at most {longest} characters long with the file backend, so that its key paths fit the Windows path limit, but {} is {length}",
                work_dir.display()
            );
        }
        let credential = app_credential(
            self.app_key,
            self.app_secret,
            ["--app-key", "--app-secret", "AGENT_IDENTITY_CONFORMANCE_APP_SECRET"],
        )?
        .context("--app-key is required")?;
        let target = Target::new(
            self.base_url.context("--base-url is required")?,
            credential,
            self.ca_path.as_deref(),
            self.authority_id.as_deref(),
        )?;
        let mut targets = vec![("--base-url".to_owned(), target, profile)];
        let second_credential = app_credential(
            self.second_app_key,
            self.second_app_secret,
            [
                "--second-app-key",
                "--second-app-secret",
                "AGENT_IDENTITY_CONFORMANCE_SECOND_APP_SECRET",
            ],
        )?;
        match (self.second_base_url, second_credential) {
            (Some(url), Some(credential)) => targets.push((
                "--second-base-url".to_owned(),
                Target::new(
                    url,
                    credential,
                    self.second_ca_path.as_deref(),
                    self.second_authority_id.as_deref(),
                )?,
                profile,
            )),
            (None, None) => ensure!(
                self.second_authority_id.is_none(),
                "--second-authority-id requires a second target"
            ),
            _ => anyhow::bail!("--second-base-url and --second-app-key must be supplied together"),
        }
        for (spec, position) in self.authorities.iter().zip(1..) {
            let spec = AuthoritySpec::parse(spec, &|name| env::var(name).ok())?;
            let target = Target::new(
                spec.base_url,
                AppCredential::new(spec.app_key, spec.app_secret),
                spec.ca_path.as_deref(),
                spec.authority_id.as_deref(),
            )?;
            targets.push((format!("--authority {position}"), target, spec.profile));
        }
        let unprivileged = app_credential(
            self.unprivileged_app_key,
            self.unprivileged_app_secret,
            [
                "--unprivileged-app-key",
                "--unprivileged-app-secret",
                "AGENT_IDENTITY_CONFORMANCE_UNPRIVILEGED_APP_SECRET",
            ],
        )?;
        let rotation_windows = targets
            .iter()
            .map(|(_, _, profile)| profile.rotation_window_secs())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut authorities = Vec::with_capacity(targets.len());
        for ((name, target, profile), rotation_window_secs) in targets.into_iter().zip(rotation_windows) {
            if kind == TargetKind::Mock {
                target.reset().await?;
            }
            let channel_available = profile.expect_channel || target.channel_available().await?;
            // A test leaf lifetime can be a whole number of days too, so only the settings show whether the leaves follow them.
            let lifetime_from_settings = kind == TargetKind::Dvls && profile.disposable && {
                let days = target.management().settings().await?.certificate_lifetime_days;
                days.checked_mul(authority::DAY_SECS) == Some(profile.leaf_lifetime_secs)
            };
            authorities.push(Authority {
                name,
                target,
                profile,
                channel_available,
                lifetime_from_settings,
                rotation_window_secs,
            });
        }
        tokio::fs::create_dir_all(&self.work_dir).await?;
        Ok(Suite {
            authorities,
            target_kind: kind,
            key_name_prefix,
            agent_version: self.agent_version,
            unprivileged: unprivileged.map(|credential| Arc::new(dvls::Session::new(credential))),
            agent_bin: self.agent_bin.context("--agent-bin is required")?,
            key_backend: self.key_backend,
            work_dir: self.work_dir,
        })
    }
}

/// The application identity a key flag names, with its secret from the secret flag or else from the environment variable.
///
/// A key without a secret, or a secret flag without a key, is a usage error.
fn app_credential(
    key: Option<String>,
    secret: Option<String>,
    [key_flag, secret_flag, secret_variable]: [&str; 3],
) -> anyhow::Result<Option<AppCredential>> {
    let Some(key) = key else {
        ensure!(secret.is_none(), "{secret_flag} requires {key_flag}");
        return Ok(None);
    };
    let secret = secret
        .or_else(|| env::var(secret_variable).ok().filter(|secret| !secret.is_empty()))
        .with_context(|| format!("{key_flag} requires {secret_flag} or {secret_variable}"))?;
    Ok(Some(AppCredential::new(key, secret)))
}

/// The longest path that Windows file APIs accept without long-path support, in UTF-16 code units: `MAX_PATH` without its terminating NUL.
#[cfg(any(windows, test))]
const WINDOWS_MAX_PATH_LEN: usize = 259;

/// The longest work directory, in UTF-16 code units, under which the file backend's key files stay within [`WINDOWS_MAX_PATH_LEN`].
///
/// A key file is `<work-dir>\<agent data dir>\identity\keys\<file name>`, for a key name `<key_name_prefix>_<UUID>`.
/// The device-key intent ("Key name") keeps every file name the file backend derives from a key name within 255 characters for the longest key name, of 193 characters, so a derived file name is at most 62 characters longer than its key name.
#[cfg(any(windows, test))]
fn longest_file_backend_work_dir(key_name_prefix: &str) -> usize {
    let file_name = key_name_prefix.len() + 1 /* _ */ + uuid::fmt::Hyphenated::LENGTH + 62 /* derived suffix */;
    let below_work_dir = 1 /* \ */
        + agent::DATA_DIR_PREFIX.len()
        + agent::DATA_DIR_RANDOM_LEN
        + 1 /* \ */
        + 8 /* identity */
        + 1 /* \ */
        + 4 /* keys */
        + 1 /* \ */
        + file_name;
    WINDOWS_MAX_PATH_LEN.saturating_sub(below_work_dir)
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring crypto provider");
    if let Err(error) = run().await {
        eprintln!("conformance runner error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    #[cfg(windows)]
    if env::args_os()
        .nth(1)
        .is_some_and(|flag| flag == std::ffi::OsStr::new("--system-probe"))
    {
        let mut args = env::args_os().skip(2);
        let request = PathBuf::from(args.next().context("--system-probe requires a request path")?);
        let result = PathBuf::from(args.next().context("--system-probe requires a result path")?);
        ensure!(args.next().is_none(), "--system-probe accepts exactly two paths");
        return system_probe::run(&request, &result);
    }
    let options = Options::parse(env::args().skip(1))?;
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
    let suite = tokio::time::timeout(RUN_DEADLINE, options.suite())
        .await
        .context("conformance setup exceeded the 14-minute-30-second deadline")??;
    println!("KEY NAME PREFIX {}", suite.key_name_prefix);
    // The Windows software provider keeps the agent's keys as machine keys, which only an elevated administrator can create.
    #[cfg(windows)]
    let machine_keys_denied =
        suite.key_backend == KeyBackend::WindowsSoftwareProvider && !windows::running_as_elevated_administrator()?;
    #[cfg(not(windows))]
    let machine_keys_denied = false;
    let mut totals = [0u32; 4];
    let mut protocol_elapsed = Duration::ZERO;
    let mut agent_elapsed = Duration::ZERO;
    let mut non_pass = Vec::new();
    let mut deadline_exceeded = false;
    for test in selected {
        let test_start = Instant::now();
        let outcome = if test.name == "a_unavailable_key_backend_stops_identity" && cfg!(windows) {
            Outcome::NotApplicable("Windows software provider is available on Windows")
        } else if test.name == "a_key_non_exportable" && !cfg!(windows) {
            Outcome::NotApplicable("Windows software provider test")
        } else if test.name == "a_file_backend_permissions" && !cfg!(unix) {
            Outcome::NotApplicable("Unix file-backend test")
        } else if let Some(reason) = dvls::unsupported(suite.target_kind, test.mock_only) {
            Outcome::NotApplicable(reason)
        } else {
            match authority::pick(&suite.authorities, &test.needs(), test.needs_second, suite.mock()) {
                Err(reason) => Outcome::Skip(reason),
                Ok(_)
                    if test.name == "a_key_non_exportable"
                        && suite.key_backend != KeyBackend::WindowsSoftwareProvider =>
                {
                    Outcome::Skip("requires --key-backend windows-software-provider")
                }
                Ok(_) if test.name == "a_file_backend_permissions" && suite.key_backend != KeyBackend::File => {
                    Outcome::Skip("requires --key-backend file")
                }
                // UNTESTED: an unelevated run with the Windows software provider reports each test that starts the agent as SKIP.
                // The agent fails to create its machine keys there, so a FAIL would blame the agent for the runner's missing privilege.
                // CI runs elevated, so check this by hand from an unelevated shell when changing which tests start the agent.
                Ok(_) if test.starts_agent && machine_keys_denied => {
                    Outcome::Skip("the Windows software provider's machine keys require an elevated administrator")
                }
                Ok((primary, second)) => {
                    if 0 < primary || second.is_some_and(|second| second != 1) {
                        let names = [Some(primary), second]
                            .into_iter()
                            .flatten()
                            .map(|index| suite.authorities[index].name.as_str())
                            .collect::<Vec<_>>();
                        println!("AUTHORITY {} {}", test.name, names.join(" "));
                    }
                    let (outcome, exceeded) = run_test(test, suite.context(test.name, primary, second), deadline).await;
                    deadline_exceeded = exceeded;
                    outcome
                }
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
    // Logging out only closes sessions that would expire anyway, so its failure never fails the run.
    if tokio::time::timeout(Duration::from_secs(5), log_out(&suite))
        .await
        .is_err()
    {
        eprintln!("WARN Logging out of the management API timed out");
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

/// Runs `test` with `context` within its timeout, which the global `deadline` shortens; the flag reports whether the deadline ended it.
async fn run_test(test: &Test, context: Context, deadline: Instant) -> (Outcome, bool) {
    let result = async {
        if context.mock() {
            context.target.reset().await?;
            if let Some(second) = &context.second {
                second.target.reset().await?;
            }
        }
        (test.run)(context.clone()).await
    };
    let timeout = if test.name == "p_channel_no_hello_timeout" {
        Duration::from_secs(20)
    } else if test.name == "a_key_non_exportable" && cfg!(windows) {
        Duration::from_secs(240)
    } else if test.name == "a_rotation_migrates_on_schedule" {
        Duration::from_secs(120)
    } else if !context.mock() && test.name.starts_with("a_rotation_") {
        Duration::from_secs(context.dvls_rotation_window_secs.saturating_add(60))
    } else if !context.mock() && test.name.starts_with("p_rotation_") {
        Duration::from_secs(context.dvls_rotation_window_secs.saturating_add(30))
    } else {
        TEST_TIMEOUT
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let allowed = timeout.min(remaining);
    match tokio::time::timeout(allowed, result).await {
        Ok(Ok(())) => (Outcome::Pass, false),
        Ok(Err(error)) => {
            let outcome = if let Some(inapplicable) = error.downcast_ref::<NotApplicable>() {
                Outcome::NotApplicable(inapplicable.0)
            } else if let Some(incomplete) = error.downcast_ref::<Incomplete>() {
                Outcome::Skip(incomplete.0)
            } else {
                Outcome::Fail(format!("{error:#}"))
            };
            (outcome, false)
        }
        Err(_) if allowed == remaining => (
            Outcome::Fail("global 14-minute-30-second deadline exceeded".to_owned()),
            true,
        ),
        Err(_) => (Outcome::Fail("timed out".to_owned()), false),
    }
}

/// Closes the run's management API sessions on every authority.
async fn log_out(suite: &Suite) {
    let unprivileged = suite.unprivileged.as_deref().and_then(|session| {
        suite
            .authorities
            .first()
            .map(|first| first.target.management_as(dvls::Credential::Session(session)))
    });
    let managements = suite
        .authorities
        .iter()
        .map(|authority| authority.target.management())
        .chain(unprivileged);
    for management in managements {
        if let Err(error) = management.log_out().await {
            eprintln!("WARN Failed to log out of the management API: {error:#}");
        }
    }
}

enum Outcome {
    Pass,
    Fail(String),
    Skip(&'static str),
    NotApplicable(&'static str),
}

#[derive(Debug)]
pub(crate) struct NotApplicable(pub(crate) &'static str);

impl std::fmt::Display for NotApplicable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for NotApplicable {}

#[derive(Debug)]
pub(crate) struct Incomplete(pub(crate) &'static str);

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Incomplete {}

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
    p!(p_enroll_malformed_authorization_rejected),
    p!(p_token_expired, mock_only),
    p!(p_enroll_idempotent_same_key),
    p!(p_token_config_contributes_to_effective_config),
    p!(p_deleted_token_replays_own_key_only),
    p!(p_enroll_revoked_same_key_rejected),
    p!(p_enroll_certificate_key_reuse_rules),
    p!(p_renew_certificate_key_reuse_rules),
    p!(p_metadata_limits),
    p!(p_friendly_name_format),
    p!(p_friendly_name_white_space_and_truncation),
    p!(p_duplicate_json_members_rejected),
    p!(p_json_body_nesting_limit),
    p!(p_invalid_unicode_json_strings_rejected),
    p!(p_noncanonical_base64_csr_rejected),
    p!(p_token_secret_must_match_exactly),
    p!(p_compressed_point_csr_rejected),
    p!(p_identity_cannot_impersonate_another),
    p!(p_channel_hello_cannot_impersonate_another).channel(),
    p!(p_renew_digest_integrity),
    p!(p_signature_parameter_order_accepted_renew),
    p!(p_signature_parameter_order_accepted_connect).channel(),
    p!(p_renew_rejects_sha384_csr),
    p!(p_same_tag_covered_components_rejected),
    p!(p_same_tag_connect_components_rejected).channel(),
    p!(p_extra_signature_parameters_rejected_renew),
    p!(p_extra_signature_parameters_rejected_connect).channel(),
    p!(p_signature_parser_wire_negatives),
    p!(p_signature_noncanonical_base64_rejected),
    p!(p_signature_repeated_raw_items_rejected),
    p!(p_connect_signature_noncanonical_or_repeated_rejected).channel(),
    p!(p_replay_nonce_rejected),
    p!(p_replay_window_rejected),
    p!(p_connect_signature_replayed_to_renew),
    p!(p_renew_signature_rejected_on_connect).channel(),
    p!(p_channel_duplicate_signature_metadata_rejected).channel(),
    p!(p_confirm_cross_tag_signatures_rejected),
    p!(p_confirm_signature_rejected_on_connect).channel(),
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
    p!(p_channel_agent_message_refreshes_last_seen).channel(),
    p!(p_handshake_barrier_holds_authentication, mock_only).channel(),
    p!(p_channel_proof_replay_fails).channel(),
    p!(p_channel_revoked_before_hello).channel(),
    p!(p_channel_deleted_before_hello).channel(),
    p!(p_channel_no_hello_timeout).channel(),
    p!(p_channel_hello_invalid_metadata_rejected).channel(),
    p!(p_channel_undecodable_first_message_rejected).channel(),
    p!(p_channel_undecodable_message_after_welcome_rejected).channel(),
    p!(p_channel_clock_skew_refusal_carries_server_time).channel(),
    p!(p_channel_server_time_corrects_skew, mock_only).channel(),
    p!(p_channel_unavailable_no_channel_url, mock_only),
    p!(p_mock_malformed_https_channel_urls, mock_only),
    p!(p_config_revision_monotonic_changes, mock_only).channel(),
    p!(p_config_hello_reconciles_stale_revision)
        .channel()
        .need(Need::ConfigChange),
    p!(p_config_update_pushes_higher_revision, mock_only).channel(),
    p!(p_request_renewal_connected_and_on_connect).channel(),
    p!(p_request_renewal_flag_cleared_only_on_confirm),
    p!(p_request_renewal_flag_cleared_after_new_cert).channel(),
    p!(p_reconnect_push_and_handoff, mock_only).channel(),
    p!(p_revocation_closes_stream).channel(),
    p!(p_stream_closes_at_not_after).channel().need(Need::ShortLeaves),
    p!(p_expired_certificate_refused_at_stream_open, mock_only).channel(),
    p!(p_challenged_stream_expires_on_advance, mock_only).channel(),
    p!(p_pending_cert_auth_does_not_promote).channel(),
    p!(p_confirm_reconnects_and_closes_retired_stream_at_grace, mock_only).channel(),
    p!(p_channel_retired_before_hello_completes_then_reconnects, mock_only).channel(),
    p!(p_rotation_publishes_both_roots_and_issues_from_new),
    p!(p_rotation_status_counts),
    p!(p_rotation_conflict_409),
    p!(p_rotation_completes_early_when_last_identity_migrates, mock_only),
    p!(p_rotation_completes_immediately_without_old_root_identities, mock_only),
    p!(p_rotation_deadline_bound, mock_only),
    p!(p_rotation_disposable_deadline_above_own_max_rejected),
    p!(p_rotation_disposable_completes_before_future_deadline),
    p!(p_rotation_grace_renewal_after_early_completion, mock_only),
    p!(p_rotation_completes_early_at_certificate_expiry_via_freeze, mock_only),
    p!(p_rotation_push_rate_survives_deadline, mock_only).channel(),
    p!(p_rotation_deadline_removes_old_root),
    p!(p_rotation_old_root_cert_renewable_after_deadline, mock_only),
    p!(p_rotation_emergency_deadline),
    p!(p_rotation_request_renewal_pushed).channel(),
    p!(p_rotation_pending_only_old_root_receives_push, mock_only).channel(),
    p!(p_listing_pagination_stable_during_concurrent_enrollment),
    p!(p_listing_views_filters_and_bounds),
    p!(p_identity_statuses, mock_only),
    p!(p_management_tokens_crud_and_states),
    p!(p_management_requires_auth),
    p!(p_management_permission_denied),
    p!(p_rotation_start_requires_auth),
    p!(p_token_expiry_default_and_maximum),
    p!(p_rotation_without_root_conflicts, mock_only),
    p!(p_root_key_unavailable_conflicts, mock_only),
    p!(p_settings_read),
    p!(p_settings_change_bounds).need(Need::Disposable),
    p!(p_settings_certificate_lifetime_applies_to_new_certificates)
        .need(Need::Disposable)
        .need(Need::SettingsLifetime),
    p!(p_settings_channel_switch_withdraws_and_restores_channel_url)
        .channel()
        .need(Need::Disposable),
    p!(p_error_body_shape),
    p!(p_authentication_error_precedes_invalid_body),
    p!(p_oversized_body_precedes_authentication),
    p!(p_mock_fault_response_not_processed, mock_only),
    a!(a_pending_file_enroll_success),
    a!(a_bad_pending_files_do_not_reject_valid_tokens),
    a!(a_undecryptable_pending_file_does_not_reject_token, mock_only),
    a!(a_untrusted_tls_server_keeps_pending_token, mock_only).second(),
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
    a!(a_unavailable_key_backend_stops_identity),
    a!(a_renew_transient_failures_retry_without_state_change, mock_only).channel(),
    a!(a_check_in_transient_failures_retry_without_state_change, mock_only),
    a!(a_token_never_logged),
    a!(a_same_token_no_enrollment),
    a!(a_same_token_after_token_exhausted_no_enrollment),
    a!(a_same_token_after_token_invalid_no_enrollment),
    a!(a_same_token_after_token_malformed_no_enrollment),
    a!(a_same_token_after_identity_revoked_no_enrollment, mock_only),
    a!(a_same_token_rejected_identity_no_enrollment).channel(),
    a!(a_different_token_replaces_identity),
    a!(a_rejected_identity_replaced).channel(),
    a!(a_cli_identity_enroll_writes_pending_file).cli_only(),
    a!(a_cli_identity_enroll_stdin).cli_only(),
    a!(a_renewal_happy_path).channel().need(Need::LongLeaves),
    a!(a_renewal_lost_response_retried, mock_only).channel(),
    a!(a_renewal_lost_confirm_response_retried, mock_only).channel(),
    a!(a_confirm_barrier_blocks_channelless_traffic, mock_only),
    a!(a_confirm_expired_pending_renews_with_fresh_key, mock_only),
    a!(a_confirm_expired_pending_beyond_grace_rejects, mock_only),
    a!(a_expired_current_renews_in_grace_or_rejects_beyond, mock_only).channel(),
    a!(a_channel_connected_and_metadata).channel(),
    a!(a_make_before_break_on_renewal).channel(),
    a!(a_old_key_deleted_after_confirm_without_channel, mock_only).channel(),
    a!(a_request_renewal_connected).channel().need(Need::LongLeaves),
    a!(a_request_renewal_while_offline).channel(),
    a!(a_request_renewal_without_channel).without_channel(),
    a!(a_reconnect_make_before_break, mock_only).channel(),
    a!(a_revocation_stops_agent).channel(),
    a!(a_identity_unknown_recorded, mock_only).channel(),
    a!(a_signed_rejection_without_live_stream, mock_only),
    a!(a_no_channel_when_absent, mock_only),
    a!(a_no_channel_url_with_query, mock_only),
    a!(a_no_channel_url_with_fragment, mock_only),
    a!(a_config_update_disables_channel, mock_only).channel(),
    a!(a_check_in_enables_channel, mock_only),
    a!(a_check_in_recovers_broken_channel, mock_only),
    a!(a_config_unknown_fields_and_hello_revision, mock_only).channel(),
    a!(a_config_unsupported_version_keeps_stored_config, mock_only),
    a!(a_config_unsupported_version_on_enroll_keeps_pending, mock_only),
    a!(a_multi_authority).second().channel().need(Need::LongLeaves),
    a!(a_key_non_exportable),
    a!(a_file_backend_permissions),
    a!(a_rotation_migrates_connected_agent).channel(),
    a!(a_rotation_migrates_through_check_in, mock_only),
    a!(a_rotation_migrates_on_schedule, mock_only),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A usage error lands in CI logs, so a credential given in a form the runner does not take, such as `--app-secret=<secret>` or a stray argument, must not appear in it.
    #[test]
    fn usage_errors_never_echo_a_credential() {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        let secret = "synthetic-credential";
        let mut cases: Vec<Vec<String>> = [
            "--app-key",
            "--app-secret",
            "--second-app-key",
            "--second-app-secret",
            "--unprivileged-app-key",
            "--unprivileged-app-secret",
            "--authority",
        ]
        .into_iter()
        .flat_map(|flag| {
            let joined = format!("{flag}={secret}");
            [vec![joined.clone()], vec![joined, "--list".to_owned()]]
        })
        .collect();
        cases.push(vec!["--app-key".to_owned(), "key".to_owned(), secret.to_owned()]);
        cases.push(vec![
            "--app-key".to_owned(),
            "key".to_owned(),
            secret.to_owned(),
            "--list".to_owned(),
        ]);
        for args in cases {
            let error = Options::parse(args.clone()).err().map(|error| format!("{error:#}"));
            assert!(
                error.as_ref().is_some_and(|error| !error.contains(secret)),
                "{args:?} gave {error:?}"
            );
        }
    }

    /// The rotation window that `args` select.
    fn rotation_window(args: &[&str]) -> anyhow::Result<u64> {
        Options::parse(args.iter().map(|arg| (*arg).to_owned()))?
            .profile()
            .rotation_window_secs()
    }

    /// A DVLS under test issues leaves of a few seconds, so the default window must stay below a short leaf lifetime, while an explicit window wins in either flag order.
    #[test]
    fn rotation_window_follows_a_short_leaf_lifetime_unless_explicit() -> anyhow::Result<()> {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        assert_eq!(rotation_window(&[])?, 60);
        assert_eq!(rotation_window(&["--leaf-lifetime-secs", "20"])?, 15);
        assert_eq!(rotation_window(&["--leaf-lifetime-secs", "2"])?, 1);
        assert_eq!(
            rotation_window(&["--dvls-rotation-window-secs", "18", "--leaf-lifetime-secs", "20"])?,
            18
        );
        Ok(())
    }

    /// 75% of a one-second leaf lifetime holds no whole second, and rounding the window up to one second would ask DVLS for a deadline it refuses.
    #[test]
    fn one_second_leaf_lifetime_requires_an_explicit_rotation_window() {
        // oracle: intent crates/agent-identity-conformance/INTENT.md §Shape
        assert!(rotation_window(&["--leaf-lifetime-secs", "1"]).is_err());
    }

    /// A key file path is `<work-dir>\identity-agent-XXXXXX\identity\keys\<file name>`: 22, 15 and at most 143 characters below the work directory for a run's 81-character key names, which leaves 79 of the 259.
    #[test]
    fn file_backend_work_dir_leaves_room_for_the_longest_key_file() {
        // oracle: intent crates/device-key/INTENT.md §Key name
        // oracle: spec Microsoft "Naming Files, Paths, and Namespaces" §Maximum Path Length Limitation
        assert_eq!(
            longest_file_backend_work_dir(&format!("conformance-{}", "0".repeat(32))),
            79
        );
    }
}
