#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

// Used by the jetsocat library.
#[cfg(feature = "native-tls")]
use native_tls as _;
#[cfg(all(feature = "native-tls", not(any(target_os = "windows", target_vendor = "apple"))))]
use openssl as _;
#[cfg(feature = "detect-proxy")]
use proxy_cfg as _;
#[cfg(windows)]
use windows as _;
use {
    base64 as _, futures_util as _, jet_proto as _, jmux_proto as _, openssl_probe as _, proxy_http as _,
    proxy_socks as _, proxy_types as _, rustls_pemfile as _, tinyjson as _, tokio_tungstenite as _, transport as _,
};
#[cfg(feature = "rustls")]
use {rustls as _, rustls_native_certs as _};

// Used by tests
#[cfg(test)]
use {proptest as _, test_utils as _};

#[macro_use]
extern crate tracing;

use anyhow::Context as _;
use jetsocat::listener::ListenerMode;
use jetsocat::pipe::PipeMode;
use jetsocat::proxy::{detect_proxy, ProxyConfig, ProxyType};
use jetsocat::DoctorOutputFormat;
use jmux_proxy::JmuxConfig;
use seahorse::{App, Command, Context, Flag, FlagType};
use std::env;
use std::future::Future;
use std::path::PathBuf;
use tokio::runtime;

fn main() {
    let args: Vec<String> = if let Ok(args_str) = env::var("JETSOCAT_ARGS") {
        env::args()
            .take(1)
            .chain(parse_env_variable_as_args(&args_str))
            .collect()
    } else {
        env::args().collect()
    };

    let app = App::new(env!("CARGO_PKG_NAME"))
        .description(env!("CARGO_PKG_DESCRIPTION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .version(env!("CARGO_PKG_VERSION"))
        .usage(generate_usage())
        .command(forward_command())
        .command(jmux_proxy())
        .command(doctor());

    app.run(args);
}

fn generate_usage() -> String {
    #[cfg(debug_assertions)]
    const IS_DEBUG: bool = true;
    #[cfg(not(debug_assertions))]
    const IS_DEBUG: bool = false;

    format!(
        "{command} [subcommand]\n\
        \n\
        \tExample: unauthenticated PowerShell\n\
        \n\
        \t  {command} forward tcp-listen://127.0.0.1:5002 cmd://'pwsh -sshs -NoLogo -NoProfile'\n\
        \n\
        \tFor detailed logs, use the `JETSOCAT_LOG` environment variable:\n\
        \n\
        \t  JETSOCAT_LOG=target[span{{field=value}}]=level\n\
        \n\
        Build type: {build}",
        command = env!("CARGO_PKG_NAME"),
        build = if IS_DEBUG { "debug" } else { "release" },
    )
}

pub fn run<F: Future<Output = anyhow::Result<()>>>(f: F) -> anyhow::Result<()> {
    // Install the default crypto provider when rustls is used.
    #[cfg(feature = "rustls")]
    if rustls::crypto::ring::default_provider().install_default().is_err() {
        let installed_provider = rustls::crypto::CryptoProvider::get_default();
        debug!(?installed_provider, "default crypto provider is already installed");
    }

    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("runtime build failed")?;

    match rt.block_on(async {
        tokio::select! {
            res = f => res,
            res = tokio::signal::ctrl_c() => res.context("ctrl-c event"),
        }
    }) {
        Ok(()) => info!("Terminated successfully"),
        Err(e) => {
            error!("{:#}", e);
            return Err(e);
        }
    }

    rt.shutdown_timeout(std::time::Duration::from_millis(100)); // Just to be safe.

    Ok(())
}

pub fn exit(res: anyhow::Result<()>) -> ! {
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    }
}

const PIPE_FORMATS: &str = r#"Pipe formats:
    `stdio` or `-`: Standard input output
    `cmd://<COMMAND>`: Spawn a new process with specified command using `cmd /C` on windows or `sh -c` otherwise
    `write-file://<PATH>`: Open specified file in write mode
    `read-file://<PATH>`: Open specified file in read mode
    `tcp://<ADDRESS>`: Plain TCP stream
    `tcp-listen://<BINDING ADDRESS>`: TCP listener
    `jet-tcp-connect://<ADDRESS>/<ASSOCIATION ID>/<CANDIDATE ID>`: TCP stream over JET protocol as client
    `jet-tcp-accept://<ADDRESS>/<ASSOCIATION ID>/<CANDIDATE ID>`: TCP stream over JET protocol as server
    `ws://<URL>`: WebSocket
    `wss://<URL>`: WebSocket Secure
    `ws-listen://<BINDING ADDRESS>`: WebSocket listener
    `np://<SERVER NAME>/pipe/<PIPE NAME>`: Connect to a named pipe (Windows)
    `np-listen://./pipe/<PIPE NAME>`: Open a named pipe and listen on it (Windows)
    `np://<UNIX SOCKET PATH>`: Connect to a UNIX socket (non-Windows)
    `np-listen://<UNIX SOCKET PATH>`: Create a UNIX socket and listen on it (non-Windows)"#;

// forward

const FORWARD_SUBCOMMAND: &str = "forward";

fn forward_command() -> Command {
    let usage = format!(
        r##"{command} {subcommand} <PIPE A> <PIPE B>

{pipe_formats}

Example: unauthenticated PowerShell server

    {command} {subcommand} tcp-listen://127.0.0.1:5002 cmd://'pwsh -sshs -NoLogo -NoProfile'

Example: unauthenticated sftp server

    {command} {subcommand} tcp-listen://0.0.0.0:2222 cmd://'/usr/lib/openssh/sftp-server'

Example: unauthenticated sftp client

    JETSOCAT_ARGS="{subcommand} - tcp://192.168.122.178:2222" sftp -D {command}"##,
        command = env!("CARGO_PKG_NAME"),
        pipe_formats = PIPE_FORMATS,
        subcommand = FORWARD_SUBCOMMAND,
    );

    let cmd = Command::new(FORWARD_SUBCOMMAND)
        .description("Pipe two streams together")
        .alias("f")
        .usage(usage)
        .action(forward_action);

    apply_common_flags(apply_forward_flags(cmd))
}

pub fn forward_action(c: &Context) {
    let res = ForwardArgs::parse(c).and_then(|args| {
        let _log_guard = setup_logger(&args.common.logging);

        let cfg = jetsocat::ForwardCfg {
            pipe_a_mode: args.pipe_a_mode,
            pipe_b_mode: args.pipe_b_mode,
            repeat_count: args.repeat_count,
            pipe_timeout: args.common.pipe_timeout,
            watch_process: args.common.watch_process,
            proxy_cfg: args.common.proxy_cfg,
        };

        run(jetsocat::forward(cfg))
    });
    exit(res);
}

// jmux-proxy

const JMUX_PROXY_SUBCOMMAND: &str = "jmux-proxy";

fn jmux_proxy() -> Command {
    let usage = format!(
        r##"{command} {subcommand} <PIPE> [<LISTENER> ...]

{pipe_formats}

Listener formats:
    - tcp-listen://<BINDING ADDRESS>/<DESTINATION URL>
    - socks5-listen://<BINDING ADDRESS>
    - http-listen://<BINDING ADDRESS>

Example: JMUX proxy

    {command} {subcommand} tcp-listen://0.0.0.0:7772 --allow-all

Example: TCP to JMUX proxy

    {command} {subcommand} tcp://127.0.0.1:7772 tcp-listen://0.0.0.0:5002/neverssl.com:80 tcp-listen://0.0.0.0:5003/crates.io:443

Example: SOCKS5 to JMUX proxy

    {command} {subcommand} tcp://127.0.0.1:7772 socks5-listen://0.0.0.0:2222"##,
        command = env!("CARGO_PKG_NAME"),
        subcommand = JMUX_PROXY_SUBCOMMAND,
        pipe_formats = PIPE_FORMATS,
    );

    let cmd = Command::new(JMUX_PROXY_SUBCOMMAND)
        .description("Start a JMUX proxy redirecting TCP streams")
        .alias("jp")
        .usage(usage)
        .action(jmux_proxy_action);

    apply_jmux_flags(apply_common_flags(cmd))
}

pub fn jmux_proxy_action(c: &Context) {
    let res = JmuxProxyArgs::parse(c).and_then(|args| {
        let _log_guard = setup_logger(&args.common.logging);

        let cfg = jetsocat::JmuxProxyCfg {
            pipe_mode: args.pipe_mode,
            proxy_cfg: args.common.proxy_cfg,
            listener_modes: args.listener_modes,
            pipe_timeout: args.common.pipe_timeout,
            watch_process: args.common.watch_process,
            jmux_cfg: args.jmux_cfg,
        };

        run(jetsocat::jmux_proxy(cfg))
    });
    exit(res);
}

// doctor

const DOCTOR_SUBCOMMAND: &str = "doctor";

fn doctor() -> Command {
    let usage = format!(
        r##"{command} {subcommand}

If the chain is not provided via the --chain option, and if the --network flag is set,
a TLS handshake will be performed with the server using --subject-name and --server-port options.
The chain file provided via the --chain option should start with the leaf certificate followed
by the intermediate certificates.

A helpful message suggesting possible fixes will be provided for common failures.

Output formats:
    - human: human-readable output
    - json: print one JSON object per line for each diagnostic

The diagonstic JSON objects have the following fields:
    - "name" (Required): A string for the name of the diagnostic.
    - "success" (Required): A boolean set to true when the diagnostic is successful and false otherwise.
    - "output" (Optional): The execution trace of the diagnostic.
    - "error" (Optional): The error returned by the diagnostic when failed.
    - "help" (Optional): A help message suggesting how to fix the issue.
    - "links" (Optional): An array of links. See the definition below.

The link JSON objects have the following fields:
    - "name" (Required): The title associated to the linked web page.
    - "href" (Required): The URL to the web page.
    - "description" (Required): A short description of the contents.

{pipe_formats}

Example: from a chain file on the disk

    {command} {subcommand} --subject-name devolutions.net --chain /path/to/chain.pem

Example: fetch the chain by connecting to the server

    {command} {subcommand} --subject-name devolutions.net --network

Example: for an invalid domain

    {command} {subcommand} --subject-name expired.badssl.com --network"##,
        command = env!("CARGO_PKG_NAME"),
        subcommand = DOCTOR_SUBCOMMAND,
        pipe_formats = PIPE_FORMATS,
    );

    let cmd = Command::new(DOCTOR_SUBCOMMAND)
        .description("Troubleshoot TLS problems")
        .usage(usage)
        .action(doctor_action);

    apply_common_flags(apply_doctor_flags(cmd))
}

pub fn doctor_action(c: &Context) {
    let res = DoctorArgs::parse(c).and_then(|args| {
        let _log_guard = setup_logger(&args.common.logging);

        let cfg = jetsocat::DoctorCfg {
            pipe_mode: args.pipe_mode,
            proxy_cfg: args.common.proxy_cfg,
            pipe_timeout: args.common.pipe_timeout,
            watch_process: args.common.watch_process,
            format: args.format,
            args: jetsocat::doctor::Args {
                server_port: args.server_port,
                subject_name: args.subject_name,
                chain_path: args.chain_path,
                allow_network: args.allow_network,
            },
        };

        run(jetsocat::doctor(cfg))
    });
    exit(res);
}

// args parsing

fn parse_env_variable_as_args(env_var_str: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut arg = String::new();
    let mut iter = env_var_str.chars();

    loop {
        match iter.next() {
            Some('"') => loop {
                // read until next "
                match iter.next() {
                    Some('"') | None => break,
                    Some(c) => arg.push(c),
                }
            },
            Some('\'') => loop {
                // read until next '
                match iter.next() {
                    Some('\'') | None => break,
                    Some(c) => arg.push(c),
                }
            },
            Some(' ') => {
                // push current arg
                args.push(std::mem::take(&mut arg));
            }
            Some(c) => arg.push(c),
            None => break,
        }
    }

    if !arg.is_empty() {
        args.push(arg);
    }

    args
}

fn apply_common_flags(cmd: Command) -> Command {
    cmd.flag(Flag::new("log-file", FlagType::String).description("Specify filepath for log file"))
        .flag(Flag::new("log-term", FlagType::Bool).description("Print logs to stdout instead of log file"))
        .flag(
            Flag::new("pipe-timeout", FlagType::String)
                .description("Timeout when opening pipes (mostly useful for listeners)"),
        )
        .flag(Flag::new("no-proxy", FlagType::Bool).description("Disable any form of proxy auto-detection"))
        .flag(Flag::new("socks4", FlagType::String).description("Use specified address:port as SOCKS4 proxy"))
        .flag(Flag::new("socks5", FlagType::String).description("Use specified address:port as SOCKS5 proxy"))
        .flag(
            Flag::new("https-proxy", FlagType::String)
                .description("Use specified address:port as HTTP tunneling proxy (also called HTTPS proxy)"),
        )
        .flag(
            Flag::new("watch-parent", FlagType::Bool).description("Watch parent process and stop piping when it dies"),
        )
        .flag(Flag::new("watch-process", FlagType::Int).description("Watch given process and stop piping when it dies"))
}

#[derive(Debug)]
enum Logging {
    Term,
    File { filepath: PathBuf, clean_old: bool },
}

struct CommonArgs {
    logging: Logging,
    proxy_cfg: Option<ProxyConfig>,
    pipe_timeout: Option<core::time::Duration>,
    watch_process: Option<sysinfo::Pid>,
}

impl CommonArgs {
    fn parse(action: &str, c: &Context) -> anyhow::Result<Self> {
        let logging = if c.bool_flag("log-term") {
            Logging::Term
        } else if let Ok(filepath) = c.string_flag("log-file") {
            let filepath = PathBuf::from(filepath);
            Logging::File {
                filepath,
                clean_old: false,
            }
        } else if let Some(mut filepath) = dirs_next::data_dir() {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("couldn't retrieve duration since UNIX epoch")?;
            filepath.push("jetsocat");
            std::fs::create_dir_all(&filepath).context("couldn't create jetsocat folder")?;
            filepath.push(format!("{}_{}", action, now.as_secs()));
            filepath.set_extension("log");
            Logging::File {
                filepath,
                clean_old: true,
            }
        } else {
            eprintln!("Couldn't retrieve data directory for log files. Enabling --no-log flag implicitly.");
            Logging::Term
        };

        let proxy_cfg = if let Ok(addr) = c.string_flag("socks5") {
            Some(ProxyConfig {
                ty: ProxyType::Socks5,
                addr,
            })
        } else if let Ok(addr) = c.string_flag("socks4") {
            Some(ProxyConfig {
                ty: ProxyType::Socks4,
                addr,
            })
        } else if let Ok(addr) = c.string_flag("https-proxy") {
            Some(ProxyConfig {
                ty: ProxyType::Https,
                addr,
            })
        } else if c.bool_flag("no-proxy") {
            None
        } else {
            detect_proxy()
        };

        let pipe_timeout = if let Ok(timeout) = c.string_flag("pipe-timeout") {
            let timeout = humantime::parse_duration(&timeout).context("invalid value for pipe timeout")?;
            Some(timeout)
        } else {
            None
        };

        let watch_process = if let Ok(process_id) = c.int_flag("watch-process") {
            let pid = u32::try_from(process_id).context("invalid value for process ID")?;
            Some(sysinfo::Pid::from_u32(pid))
        } else if c.bool_flag("watch-parent") {
            use sysinfo::{ProcessRefreshKind, RefreshKind, System};

            // Find current process' parent process ID
            let current_pid =
                sysinfo::get_current_pid().map_err(|e| anyhow::anyhow!("couldn't find current process ID: {e}"))?;
            let mut sys = System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[current_pid]), false);
            let current_process = sys.process(current_pid).expect("current process exists");
            Some(current_process.parent().context("couldn't find parent process")?)
        } else {
            None
        };

        Ok(Self {
            logging,
            proxy_cfg,
            pipe_timeout,
            watch_process,
        })
    }
}

fn apply_forward_flags(cmd: Command) -> Command {
    cmd.flag(Flag::new("repeat-count", FlagType::Int).description("How many times piping is repeated [default = 0]"))
}

struct ForwardArgs {
    common: CommonArgs,
    repeat_count: usize,
    pipe_a_mode: PipeMode,
    pipe_b_mode: PipeMode,
}

impl ForwardArgs {
    fn parse(c: &Context) -> anyhow::Result<Self> {
        let common = CommonArgs::parse(FORWARD_SUBCOMMAND, c)?;

        let repeat_count =
            usize::try_from(c.int_flag("repeat-count").unwrap_or(0)).context("bad repeat-count value")?;

        let mut args = c.args.iter();

        let arg_pipe_left = args.next().context("<PIPE A> is missing")?.clone();
        let pipe_left_mode = parse_pipe_mode(arg_pipe_left).context("bad <PIPE A>")?;

        let arg_pipe_right = args.next().context("<PIPE B> is missing")?.clone();
        let pipe_right_mode = parse_pipe_mode(arg_pipe_right).context("bad <PIPE B>")?;

        Ok(Self {
            common,
            repeat_count,
            pipe_a_mode: pipe_left_mode,
            pipe_b_mode: pipe_right_mode,
        })
    }
}

fn apply_jmux_flags(cmd: Command) -> Command {
    cmd.flag(Flag::new("allow-all", FlagType::Bool).description("Allow all redirections"))
}

struct JmuxProxyArgs {
    common: CommonArgs,
    pipe_mode: PipeMode,
    listener_modes: Vec<ListenerMode>,
    jmux_cfg: JmuxConfig,
}

impl JmuxProxyArgs {
    fn parse(c: &Context) -> anyhow::Result<Self> {
        let common = CommonArgs::parse(JMUX_PROXY_SUBCOMMAND, c)?;

        let jmux_cfg = if c.bool_flag("allow-all") {
            JmuxConfig::permissive()
        } else {
            JmuxConfig::client()
        };

        let arg_pipe = c.args.first().context("<PIPE> is missing")?.clone();
        let pipe_mode = parse_pipe_mode(arg_pipe).context("bad <PIPE>")?;

        let listener_modes = c
            .args
            .iter()
            .skip(1)
            .map(|arg| parse_listener_mode(arg).with_context(|| format!("Bad <LISTENER>: `{arg}`")))
            .collect::<anyhow::Result<Vec<ListenerMode>>>()?;

        Ok(Self {
            common,
            pipe_mode,
            listener_modes,
            jmux_cfg,
        })
    }
}

fn parse_pipe_mode(arg: String) -> anyhow::Result<PipeMode> {
    use uuid::Uuid;

    if arg == "stdio" || arg == "-" {
        return Ok(PipeMode::Stdio);
    }

    const SCHEME_SEPARATOR: &str = "://";

    let scheme_end_idx = arg
        .find(SCHEME_SEPARATOR)
        .context("invalid format: missing scheme (e.g.: tcp://<ADDRESS>)")?;
    let scheme = &arg[..scheme_end_idx];
    let value = &arg[scheme_end_idx + SCHEME_SEPARATOR.len()..];

    fn parse_jet_pipe_format(value: &str) -> anyhow::Result<(String, Uuid, Uuid)> {
        let mut it = value.split('/');
        let addr = it.next().context("address is missing")?;

        let association_id_str = it.next().context("association ID is missing")?;
        let association_id = Uuid::parse_str(association_id_str).context("bad association ID")?;

        let candidate_id_str = it.next().context("candidate ID is missing")?;
        let candidate_id = Uuid::parse_str(candidate_id_str).context("bad candidate ID")?;

        Ok((addr.to_owned(), association_id, candidate_id))
    }

    match scheme {
        "tcp-listen" => Ok(PipeMode::TcpListen {
            bind_addr: value.to_owned(),
        }),
        "cmd" => Ok(PipeMode::ProcessCmd {
            command: value.to_owned(),
        }),
        "write-file" => Ok(PipeMode::WriteFile {
            path: PathBuf::from(value.to_owned()),
        }),
        "read-file" => Ok(PipeMode::ReadFile {
            path: PathBuf::from(value.to_owned()),
        }),
        "tcp" => Ok(PipeMode::Tcp { addr: value.to_owned() }),
        "jet-tcp-connect" => {
            let (addr, association_id, candidate_id) = parse_jet_pipe_format(value)?;
            Ok(PipeMode::JetTcpConnect {
                addr,
                association_id,
                candidate_id,
            })
        }
        "jet-tcp-accept" => {
            let (addr, association_id, candidate_id) = parse_jet_pipe_format(value)?;
            Ok(PipeMode::JetTcpAccept {
                addr,
                association_id,
                candidate_id,
            })
        }
        "ws" | "wss" => Ok(PipeMode::WebSocket { url: arg }),
        "ws-listen" => Ok(PipeMode::WebSocketListen {
            bind_addr: value.to_owned(),
        }),
        "np" => {
            #[cfg(windows)]
            {
                Ok(PipeMode::NamedPipe {
                    name: format!("\\\\{}", value.replace('/', "\\")),
                })
            }
            #[cfg(unix)]
            {
                Ok(PipeMode::UnixSocket {
                    path: PathBuf::from(value.to_owned()),
                })
            }
        }
        "np-listen" => {
            #[cfg(windows)]
            {
                Ok(PipeMode::NamedPipeListen {
                    name: format!("\\\\{}", value.replace('/', "\\")),
                })
            }
            #[cfg(unix)]
            {
                Ok(PipeMode::UnixSocketListen {
                    path: PathBuf::from(value.to_owned()),
                })
            }
        }
        _ => anyhow::bail!("Unknown pipe scheme: {}", scheme),
    }
}

fn parse_listener_mode(arg: &str) -> anyhow::Result<ListenerMode> {
    const SCHEME_SEPARATOR: &str = "://";

    let scheme_end_idx = arg
        .find(SCHEME_SEPARATOR)
        .context("invalid format: missing scheme (e.g.: socks5-listen://<BINDING ADDRESS>)")?;
    let scheme = &arg[..scheme_end_idx];
    let value = &arg[scheme_end_idx + SCHEME_SEPARATOR.len()..];

    match scheme {
        "tcp-listen" => {
            let mut it = value.splitn(2, '/');
            let bind_addr = it.next().context("binding address is missing")?;
            let destination_url = it.next().context("destination URL is missing")?;

            Ok(ListenerMode::Tcp {
                bind_addr: bind_addr.to_owned(),
                destination_url: destination_url.to_owned(),
            })
        }
        "socks5-listen" => Ok(ListenerMode::Socks5 {
            bind_addr: value.to_owned(),
        }),
        "http-listen" => Ok(ListenerMode::Http {
            bind_addr: value.to_owned(),
        }),
        _ => anyhow::bail!("Unknown listener scheme: {}", scheme),
    }
}

fn apply_doctor_flags(cmd: Command) -> Command {
    cmd.flag(Flag::new("chain", FlagType::String).description("Path to a certification chain to verify"))
        .flag(Flag::new("subject-name", FlagType::String).description("Domain name to verify"))
        .flag(
            Flag::new("server-port", FlagType::Uint)
                .description("Port to use when fetching the certification chain from the server (default: 443)"),
        )
        .flag(Flag::new("pipe", FlagType::String).description("Pipe in which results should be written into"))
        .flag(Flag::new("format", FlagType::String).description("The format to use for printing the diagnostics"))
        .flag(Flag::new("network", FlagType::Bool).description("Allow network usage to perform the verifications"))
}

struct DoctorArgs {
    common: CommonArgs,
    pipe_mode: PipeMode,
    chain_path: Option<PathBuf>,
    subject_name: Option<String>,
    server_port: Option<u16>,
    format: DoctorOutputFormat,
    allow_network: bool,
}

impl DoctorArgs {
    fn parse(c: &Context) -> anyhow::Result<Self> {
        let common = CommonArgs::parse(JMUX_PROXY_SUBCOMMAND, c)?;

        let chain_path = c.string_flag("chain").map(PathBuf::from).ok();
        let subject_name = c.string_flag("subject-name").ok();

        let server_port = if let Ok(port) = c.uint_flag("server-port") {
            Some(u16::try_from(port).context("invalid port number")?)
        } else {
            None
        };

        let format = if let Ok(format) = c.string_flag("format") {
            match format.as_str() {
                "human" => DoctorOutputFormat::Human,
                "json" => DoctorOutputFormat::Json,
                _ => anyhow::bail!("unknown output format: {format}"),
            }
        } else {
            DoctorOutputFormat::Human
        };

        let pipe_mode = if let Ok(pipe) = c.string_flag("pipe") {
            parse_pipe_mode(pipe).context("bad <PIPE>")?
        } else {
            PipeMode::Stdio
        };

        let allow_network = c.bool_flag("network");

        Ok(Self {
            common,
            chain_path,
            subject_name,
            server_port,
            format,
            pipe_mode,
            allow_network,
        })
    }
}

// logging

struct LoggerGuard {
    _worker_guard: tracing_appender::non_blocking::WorkerGuard,
}

fn setup_logger(logging: &Logging) -> LoggerGuard {
    use std::fs::OpenOptions;
    use std::panic;
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let (layer, guard) = match &logging {
        Logging::Term => {
            let (non_blocking_stdio, guard) = tracing_appender::non_blocking(std::io::stdout());
            let stdio_layer = fmt::layer().with_writer(non_blocking_stdio);
            (stdio_layer, guard)
        }
        Logging::File { filepath, clean_old: _ } => {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(filepath)
                .expect("couldn't create log file");

            let (non_blocking, guard) = tracing_appender::non_blocking(file);
            let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);

            (file_layer, guard)
        }
    };

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .with_env_var("JETSOCAT_LOG")
        .from_env()
        .expect("invalid filtering directive from env");

    tracing_subscriber::registry().with(layer).with(env_filter).init();

    info!(version = env!("CARGO_PKG_VERSION"));

    panic::set_hook(Box::new(move |panic_info| {
        error!(%panic_info);
        eprintln!("{panic_info}");
    }));

    warn_span!("clean_old_log_files", file_name = tracing::field::Empty,).in_scope(|| {
        debug!(?logging);
        if let Err(error) = clean_old_log_files(logging) {
            warn!(error = format!("{error:#}"), "Failed to clean old log files")
        }
    });

    LoggerGuard { _worker_guard: guard }
}

fn clean_old_log_files(logging: &Logging) -> anyhow::Result<()> {
    use std::time::Duration;
    use std::{fs, io, path};

    const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 5); // 5 days

    let folder = if let Logging::File {
        filepath,
        clean_old: true,
    } = &logging
    {
        filepath.parent().context("invalid log path")?
    } else {
        return Ok(());
    };

    let read_dir = fs::read_dir(folder).context("failed to read directory")?;

    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, "Couldn't read next file");
                continue;
            }
        };

        let file_name = entry.file_name();
        let file_path = path::Path::new(&file_name);

        let _entered = info_span!("found_candidate", file_name = %file_path.display()).entered();

        match file_path.extension().and_then(|ext| ext.to_str()) {
            Some("log") => {
                debug!("Found a log file");
            }
            _ => continue,
        }

        match entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .and_then(|time| time.elapsed().map_err(|e| io::Error::new(io::ErrorKind::Other, e)))
        {
            Ok(modified) if modified > MAX_AGE => {
                info!("Delete log file");
                if let Err(error) = fs::remove_file(entry.path()) {
                    warn!(%error, "Couldn't delete log file");
                }
            }
            Ok(_) => {
                trace!("Keep this log file");
            }
            Err(error) => {
                warn!(%error, "Couldn't retrieve metadata for file");
            }
        }
    }

    Ok(())
}
