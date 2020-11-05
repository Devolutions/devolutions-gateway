use anyhow::Context as _;
use jetsocat::pipe::PipeCmd;
use seahorse::{App, Command, Context, Flag, FlagType};
use slog::*;
use std::env;
use std::future::Future;
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
        .command(listen_command());

    app.run(args);
}

fn generate_usage() -> String {
    format!(
        "{command} [action]\n\
        \n\
        \tExample: unauthenticated powershell\n\
        \n\
        \t  {command} listen 127.0.0.1:5002 --cmd 'pwsh -sshs -NoLogo -NoProfile'",
        command = env!("CARGO_PKG_NAME")
    )
}

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

fn setup_logger(filename: &str) -> slog::Logger {
    use std::fs::OpenOptions;
    use std::panic;

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(filename)
        .expect("couldn't create log file");

    let decorator = slog_term::PlainDecorator::new(file);
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, o!("version" => env!("CARGO_PKG_VERSION")));

    let logger_cloned = logger.clone();
    panic::set_hook(Box::new(move |panic_info| {
        slog::crit!(logger_cloned, "{}", panic_info);
        eprintln!("{}", panic_info);
    }));

    logger
}

pub fn run<F: Future<Output = anyhow::Result<()>>>(log: Logger, f: F) {
    match runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("runtime build failed")
        .and_then(|rt| rt.block_on(f))
    {
        Ok(()) => info!(log, "Terminated successfuly"),
        Err(e) => {
            error!(log, "Failure: {}", e);
            eprintln!("{}", e);
        }
    };
}

// client side

fn connect_command() -> Command {
    Command::new("connect")
        .description("Connect to a jet association and pipe stdin / stdout")
        .alias("c")
        .usage(format!("{} connect ws://URL | wss://URL", env!("CARGO_PKG_NAME")))
        .action(connect_action)
}

pub fn connect_action(c: &Context) {
    let addr = c.args.first().expect("addr is missing").clone();
    let log = setup_logger("connect.log");
    run(log.clone(), jetsocat::client::connect(addr, log));
}

// server side

fn apply_server_side_flags(cmd: Command) -> Command {
    cmd.flag(
        Flag::new("sh-c", FlagType::String).description("Start specified command line using `sh -c` (even on Windows)"),
    )
    .flag(
        Flag::new("cmd", FlagType::String)
            .description("Start specified command line using `cmd /C` on windows or `sh -c` otherwise"),
    )
}

fn get_server_side_args(c: &Context) -> (String, PipeCmd) {
    let addr = c.args.first().expect("addr is missing").clone();

    let pipe = if let Ok(command_string) = c.string_flag("sh-c") {
        PipeCmd::ShC(command_string)
    } else if let Ok(command_string) = c.string_flag("cmd") {
        PipeCmd::Cmd(command_string)
    } else {
        panic!("command is missing (--sh-c OR --cmd)");
    };

    (addr, pipe)
}

fn accept_command() -> Command {
    let cmd = Command::new("accept")
        .description("Accept a jet association and pipe with powershell")
        .alias("a")
        .usage(format!("{} accept <ws://URL | wss://URL>", env!("CARGO_PKG_NAME")))
        .action(accept_action);

    apply_server_side_flags(cmd)
}

pub fn accept_action(c: &Context) {
    let (addr, pipe) = get_server_side_args(c);
    let log = setup_logger("accept.log");
    run(log.clone(), jetsocat::server::accept(addr, pipe, log));
}

fn listen_command() -> Command {
    let cmd = Command::new("listen")
        .description("Listen for an incoming connection and pipe with powershell (testing purpose only)")
        .alias("l")
        .usage(format!("{} listen BINDING_ADDRESS", env!("CARGO_PKG_NAME")))
        .action(listen_action);

    apply_server_side_flags(cmd)
}

pub fn listen_action(c: &Context) {
    let (addr, pipe) = get_server_side_args(c);
    let log = setup_logger("listen.log");
    run(log.clone(), jetsocat::server::listen(addr, pipe, log));
}
