use anyhow::Context as _;
use jetsocat::listener::ListenerMode;
use jetsocat::pipe::PipeMode;
use jetsocat::proxy::{detect_proxy, ProxyConfig, ProxyType};
use jmux_proxy::JmuxConfig;
use seahorse::{App, Command, Context, Flag, FlagType};
use slog::{crit, info, o, Logger};
use std::env;
use std::future::Future;
use std::path::PathBuf;
use tokio::runtime;

fn main() {
    let args: Vec<String> = if let Ok(args_str) = std::env::var("JETSOCAT_ARGS") {
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
        .command(jmux_proxy());

    app.run(args);
}

fn generate_usage() -> String {
    #[cfg(debug_assertions)]
    const IS_DEBUG: bool = true;
    #[cfg(not(debug_assertions))]
    const IS_DEBUG: bool = false;
    #[cfg(feature = "verbose")]
    const IS_VERBOSE: bool = true;
    #[cfg(not(feature = "verbose"))]
    const IS_VERBOSE: bool = false;

    format!(
        "{command} [action]\n\
        \n\
        \tExample: unauthenticated PowerShell\n\
        \n\
        \t  {command} forward tcp-listen://127.0.0.1:5002 cmd://'pwsh -sshs -NoLogo -NoProfile'\n\
        \n\
        For detailed logs use debug binary or any binary built with 'verbose' feature enabled.\n\
        This binary was built as:\n\
        \tDebug? {is_debug}\n\
        \tVerbose? {is_verbose}",
        command = env!("CARGO_PKG_NAME"),
        is_debug = IS_DEBUG,
        is_verbose = IS_VERBOSE,
    )
}

pub fn run<F: Future<Output = anyhow::Result<()>>>(log: Logger, f: F) -> anyhow::Result<()> {
    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("runtime build failed")?;

    match rt.block_on(f) {
        Ok(()) => info!(log, "Terminated successfully"),
        Err(e) => {
            crit!(log, "{:#}", e);
            return Err(e);
        }
    }

    rt.shutdown_timeout(std::time::Duration::from_millis(100)); // just to be safe

    Ok(())
}

pub fn exit(res: anyhow::Result<()>) -> ! {
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{:?}", e);
            std::process::exit(1);
        }
    }
}

const PIPE_FORMATS: &str = r#"Pipe formats:
    `stdio` or `-`: Standard input output
    `cmd://<COMMAND>`: Spawn a new process with specified command using `cmd /C` on windows or `sh -c` otherwise
    `tcp://<ADDRESS>`: Plain TCP stream
    `tcp-listen://<BINDING ADDRESS>`: TCP listener
    `jet-tcp-connect://<ADDRESS>/<ASSOCIATION ID>/<CANDIDATE ID>`: TCP stream over JET protocol as client
    `jet-tcp-accept://<ADDRESS>/<ASSOCIATION ID>/<CANDIDATE ID>`: TCP stream over JET protocol as server
    `ws://<URL>`: WebSocket
    `wss://<URL>`: WebSocket Secure
    `ws-listen://<BINDING ADDRESS>`: WebSocket listener"#;

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
        let log = setup_logger(args.common.logging);

        let cfg = jetsocat::ForwardCfg {
            pipe_a_mode: args.pipe_a_mode,
            pipe_b_mode: args.pipe_b_mode,
            repeat_count: args.repeat_count,
            timeout: args.common.timeout,
            proxy_cfg: args.common.proxy_cfg,
        };

        let forward_log = log.new(o!("action" => "forward"));

        run(forward_log.clone(), jetsocat::forward(cfg, forward_log))
    });
    exit(res);
}

// jmux-proxy

const JMUX_PROXY_SUBCOMMAND: &str = "jmux-proxy";

fn jmux_proxy() -> Command {
    let usage = format!(
        r##"{command} {subcommand} <PIPE> [<LISTENER> ...]

{pipe_formats}

Listener format:
    - tcp-listen://<BINDING ADDRESS>/<DESTINATION URL>
    - socks5-listen://<BINDING ADDRESS>
    - https-listen://<BINDING ADDRESS>

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
        let log = setup_logger(args.common.logging);

        let cfg = jetsocat::JmuxProxyCfg {
            pipe_mode: args.pipe_mode,
            proxy_cfg: args.common.proxy_cfg,
            listener_modes: args.listener_modes,
            timeout: args.common.timeout,
            jmux_cfg: args.jmux_cfg,
        };

        let jmux_proxy_log = log.new(o!("action" => JMUX_PROXY_SUBCOMMAND));

        run(jmux_proxy_log.clone(), jetsocat::jmux_proxy(cfg, jmux_proxy_log))
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
        .flag(Flag::new("timeout", FlagType::String).description("Timeout when opening pipes"))
        .flag(Flag::new("no-proxy", FlagType::Bool).description("Disable any form of proxy auto-detection"))
        .flag(Flag::new("socks4", FlagType::String).description("Use specified address:port as SOCKS4 proxy"))
        .flag(Flag::new("socks5", FlagType::String).description("Use specified address:port as SOCKS5 proxy"))
        .flag(Flag::new("https-proxy", FlagType::String).description("Use specified address:port as HTTPS proxy"))
}

enum Logging {
    Term,
    File { filepath: PathBuf },
}

struct CommonArgs {
    logging: Logging,
    proxy_cfg: Option<ProxyConfig>,
    timeout: Option<core::time::Duration>,
}

impl CommonArgs {
    fn parse(action: &str, c: &Context) -> anyhow::Result<Self> {
        let logging = if c.bool_flag("log-term") {
            Logging::Term
        } else if let Ok(filepath) = c.string_flag("log-file") {
            let filepath = PathBuf::from(filepath);
            Logging::File { filepath }
        } else if let Some(mut filepath) = dirs_next::data_dir() {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("Couldn't retrieve duration since UNIX epoch")?;
            filepath.push("jetsocat");
            std::fs::create_dir_all(&filepath).context("couldn't create jetsocat folder")?;
            filepath.push(format!("{}_{}", action, now.as_secs()));
            filepath.set_extension("log");
            Logging::File { filepath }
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

        let timeout = if let Ok(timeout) = c.string_flag("timeout") {
            let timeout = humantime::parse_duration(&timeout).context("Invalid value for timeout")?;
            Some(timeout)
        } else {
            None
        };

        Ok(Self {
            logging,
            proxy_cfg,
            timeout,
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
            usize::try_from(c.int_flag("repeat-count").unwrap_or(0)).context("Bad repeat-count value")?;

        let arg_pipe_a = c.args.get(0).context("<PIPE A> is missing")?.clone();
        let pipe_a_mode = parse_pipe_mode(arg_pipe_a).context("Bad <PIPE A>")?;

        let arg_pipe_b = c.args.get(1).context("<PIPE B> is missing")?.clone();
        let pipe_b_mode = parse_pipe_mode(arg_pipe_b).context("Bad <PIPE B>")?;

        Ok(Self {
            common,
            repeat_count,
            pipe_a_mode,
            pipe_b_mode,
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

        let arg_pipe = c.args.get(0).context("<PIPE> is missing")?.clone();
        let pipe_mode = parse_pipe_mode(arg_pipe).context("Bad <PIPE>")?;

        let listener_modes = c
            .args
            .iter()
            .skip(1)
            .map(|arg| parse_listener_mode(arg).with_context(|| format!("Bad <LISTENER>: `{}`", arg)))
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
        .context("Invalid format: missing scheme (e.g.: tcp://<ADDRESS>)")?;
    let scheme = &arg[..scheme_end_idx];
    let value = &arg[scheme_end_idx + SCHEME_SEPARATOR.len()..];

    fn parse_jet_pipe_format(value: &str) -> anyhow::Result<(String, Uuid, Uuid)> {
        let mut it = value.split('/');
        let addr = it.next().context("Address is missing")?;

        let association_id_str = it.next().context("Association ID is missing")?;
        let association_id = Uuid::parse_str(association_id_str).context("Bad association ID")?;

        let candidate_id_str = it.next().context("Candidate ID is missing")?;
        let candidate_id = Uuid::parse_str(candidate_id_str).context("Bad candidate ID")?;

        Ok((addr.to_owned(), association_id, candidate_id))
    }

    match scheme {
        "tcp-listen" => Ok(PipeMode::TcpListen {
            bind_addr: value.to_owned(),
        }),
        "cmd" => Ok(PipeMode::ProcessCmd {
            command: value.to_owned(),
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
        _ => anyhow::bail!("Unknown pipe scheme: {}", scheme),
    }
}

fn parse_listener_mode(arg: &str) -> anyhow::Result<ListenerMode> {
    const SCHEME_SEPARATOR: &str = "://";

    let scheme_end_idx = arg
        .find(SCHEME_SEPARATOR)
        .context("Invalid format: missing scheme (e.g.: socks5-listen://<BINDING ADDRESS>)")?;
    let scheme = &arg[..scheme_end_idx];
    let value = &arg[scheme_end_idx + SCHEME_SEPARATOR.len()..];

    match scheme {
        "tcp-listen" => {
            let mut it = value.splitn(2, '/');
            let bind_addr = it.next().context("Binding address is missing")?;
            let destination_url = it.next().context("Destination URL is missing")?;

            Ok(ListenerMode::Tcp {
                bind_addr: bind_addr.to_owned(),
                destination_url: destination_url.to_owned(),
            })
        }
        "socks5-listen" => Ok(ListenerMode::Socks5 {
            bind_addr: value.to_owned(),
        }),
        "https-listen" => Ok(ListenerMode::Https {
            bind_addr: value.to_owned(),
        }),
        _ => anyhow::bail!("Unknown listener scheme: {}", scheme),
    }
}

// logging

fn setup_logger(logging: Logging) -> slog::Logger {
    use slog::Drain;
    use std::fs::OpenOptions;
    use std::panic;

    let drain = match logging {
        Logging::Term => {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::CompactFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain).build().fuse()
        }
        Logging::File { filepath } => {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(filepath)
                .expect("couldn't create log file");
            let decorator = slog_term::PlainDecorator::new(file);
            let drain = slog_term::CompactFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain).build().fuse()
        }
    };

    let logger = slog::Logger::root(drain, o!("version" => env!("CARGO_PKG_VERSION")));

    let logger_cloned = logger.clone();
    panic::set_hook(Box::new(move |panic_info| {
        slog::crit!(logger_cloned, "{}", panic_info);
        eprintln!("{}", panic_info);
    }));

    logger
}
