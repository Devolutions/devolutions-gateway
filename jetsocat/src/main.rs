use anyhow::Context as _;
use jetsocat::pipe::PipeCmd;
use jetsocat::proxy::{detect_proxy, ProxyConfig, ProxyType};
use jetsocat::tcp_proxy::JetTcpAcceptCmd;
use seahorse::{App, Command, Context, Flag, FlagType};
use slog::{info, o, Logger};
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
        .command(connect_command())
        .command(accept_command())
        .command(listen_command())
        .command(jet_tcp_accept_command());

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
        \t  {command} listen 127.0.0.1:5002 --cmd 'pwsh -sshs -NoLogo -NoProfile'\n\
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
    rt.block_on(f)?;
    info!(log, "Terminated successfully");
    rt.shutdown_timeout(std::time::Duration::from_millis(100)); // just to be safe
    Ok(())
}

pub fn exit(res: anyhow::Result<()>) -> ! {
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

// client side

fn connect_command() -> Command {
    let cmd = Command::new("connect")
        .description("Connect to a jet association and pipe stdin / stdout")
        .alias("c")
        .usage(format!("{} connect ws://URL | wss://URL", env!("CARGO_PKG_NAME")))
        .action(connect_action);

    apply_common_flags(cmd)
}

pub fn connect_action(c: &Context) {
    let res = CommonArgs::parse("connect", c).and_then(|args| {
        let log = setup_logger(args.logging);
        run(log.clone(), jetsocat::client::connect(args.addr, args.proxy_cfg, log))
    });
    exit(res);
}

// server side

fn accept_command() -> Command {
    let cmd = Command::new("accept")
        .description("Accept a jet association and pipe with powershell")
        .alias("a")
        .usage(format!("{} accept <ws://URL | wss://URL>", env!("CARGO_PKG_NAME")))
        .action(accept_action);

    apply_common_flags(apply_server_pipe_flags(cmd))
}

pub fn accept_action(c: &Context) {
    let res = ServerArgs::parse("accept", c).and_then(|args| {
        let log = setup_logger(args.common.logging);
        run(
            log.clone(),
            jetsocat::server::accept(args.common.addr, args.cmd, args.common.proxy_cfg, log),
        )
    });
    exit(res);
}

fn listen_command() -> Command {
    let cmd = Command::new("listen")
        .description("Listen for an incoming connection and pipe with powershell (testing purpose only)")
        .alias("l")
        .usage(format!("{} listen BINDING_ADDRESS", env!("CARGO_PKG_NAME")))
        .action(listen_action);

    apply_common_flags(apply_server_pipe_flags(cmd))
}

pub fn listen_action(c: &Context) {
    let res = ServerArgs::parse("listen", c).and_then(|args| {
        let log = setup_logger(args.common.logging);
        run(log.clone(), jetsocat::server::listen(args.common.addr, args.cmd, log))
    });
    exit(res);
}

fn jet_tcp_accept_command() -> Command {
    let cmd = Command::new("jet-tcp-accept")
        .alias("p")
        .description("Reverse tcp-proxy")
        .usage(format!(
            "{} jet-tcp-accept <GATEWAY_ADDR> --forward-addr <ADDR> --association-id <UUID> --candidate-id <UUID> [--max-reconnection-count=3]",
            env!("CARGO_PKG_NAME")
        ))
        .action(jet_tcp_accept_action);
    apply_common_flags(apply_tcp_proxy_server_flags(cmd))
}

pub fn jet_tcp_accept_action(c: &Context) {
    let res = JetTcpAcceptArgs::parse("jet-tcp-accept", c).and_then(|args| {
        let log = setup_logger(args.common.logging);
        run(
            log.clone(),
            jetsocat::tcp_proxy::jet_tcp_accept(args.common.addr, args.cmd, args.common.proxy_cfg, log),
        )
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
        .flag(Flag::new("no-proxy", FlagType::Bool).description("Disable any form of proxy auto-detection"))
        .flag(Flag::new("socks4", FlagType::String).description("Use specificed address:port as SOCKS4 proxy"))
        .flag(Flag::new("socks5", FlagType::String).description("Use specificed address:port as SOCKS5 proxy"))
        .flag(Flag::new("http-proxy", FlagType::String).description("Use specificed address:port as HTTP proxy"))
}

enum Logging {
    Term,
    File { filepath: PathBuf },
}

struct CommonArgs {
    addr: String,
    logging: Logging,
    proxy_cfg: Option<ProxyConfig>,
}

impl CommonArgs {
    fn parse(action: &str, c: &Context) -> anyhow::Result<Self> {
        let addr = c.args.first().context("Address is missing")?.clone();

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
        } else if let Ok(addr) = c.string_flag("http-proxy") {
            Some(ProxyConfig {
                ty: ProxyType::Http,
                addr,
            })
        } else if c.bool_flag("no-proxy") {
            None
        } else {
            detect_proxy()
        };

        Ok(Self {
            addr,
            logging,
            proxy_cfg,
        })
    }
}

fn apply_server_pipe_flags(cmd: Command) -> Command {
    cmd.flag(
        Flag::new("sh-c", FlagType::String).description("Start specified command line using `sh -c` (even on Windows)"),
    )
    .flag(
        Flag::new("cmd", FlagType::String)
            .description("Start specified command line using `cmd /C` on windows or `sh -c` otherwise"),
    )
}

fn apply_tcp_proxy_server_flags(cmd: Command) -> Command {
    cmd.flag(Flag::new("forward-addr", FlagType::String).description("Source IP:PORT for tcp forwarding"))
        .flag(
            Flag::new("association-id", FlagType::String)
                .description("Jet association UUID for Devolutions-Gateway rendezvous connection"),
        )
        .flag(
            Flag::new("candidate-id", FlagType::String)
                .description("Jet candidate UUID for Devolutions-Gateway rendezvous connection"),
        )
        .flag(
            Flag::new("max-reconnection-count", FlagType::Int).description("Max reconnection count for tcp forwarding"),
        )
}

struct JetTcpAcceptArgs {
    common: CommonArgs,
    cmd: JetTcpAcceptCmd,
}

impl JetTcpAcceptArgs {
    fn parse(action: &str, c: &Context) -> anyhow::Result<Self> {
        let common = CommonArgs::parse(action, c)?;

        let association_id = c
            .string_flag("association-id")
            .with_context(|| "missing argument --association-id")?;
        let candidate_id = c
            .string_flag("candidate-id")
            .with_context(|| "missing argument --candidate-id")?;
        let forward_addr = c
            .string_flag("forward-addr")
            .with_context(|| "missing argument --forward-addr")?;
        let max_reconnection_count = c.int_flag("max-reconnection-count").unwrap_or(0) as usize;

        let cmd = JetTcpAcceptCmd {
            forward_addr,
            association_id,
            candidate_id,
            max_reconnection_count,
        };

        Ok(Self { common, cmd })
    }
}

struct ServerArgs {
    common: CommonArgs,
    cmd: PipeCmd,
}

impl ServerArgs {
    fn parse(action: &str, c: &Context) -> anyhow::Result<Self> {
        let common = CommonArgs::parse(action, c)?;

        let cmd = if let Ok(command_string) = c.string_flag("sh-c") {
            PipeCmd::ShC(command_string)
        } else if let Ok(command_string) = c.string_flag("cmd") {
            PipeCmd::Cmd(command_string)
        } else {
            return Err(anyhow::anyhow!("Pipe command is missing (--sh-c OR --cmd)"));
        };

        Ok(Self { common, cmd })
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
