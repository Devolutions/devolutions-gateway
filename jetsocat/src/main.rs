use anyhow::Context as _;
use seahorse::{App, Command, Context};
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
        .usage(format!("{} [command]", env!("CARGO_PKG_NAME")))
        .command(connect_command())
        .command(accept_command())
        .command(listen_command());

    app.run(args);
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
        slog::error!(logger_cloned, "{}", panic_info);
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

fn accept_command() -> Command {
    Command::new("accept")
        .description("Accept a jet association and pipe with powershell")
        .alias("a")
        .usage(format!("{} accept ws://URL | wss://URL", env!("CARGO_PKG_NAME")))
        .action(accept_action)
}

pub fn accept_action(c: &Context) {
    let addr = c.args.first().expect("addr is missing").clone();
    let log = setup_logger("accept.log");
    run(log.clone(), jetsocat::server::accept(addr, log));
}

fn listen_command() -> Command {
    Command::new("listen")
        .description("Listen for an incoming connection and pipe with powershell (testing purpose only)")
        .alias("l")
        .usage(format!("{} listen BINDING_ADDRESS", env!("CARGO_PKG_NAME")))
        .action(listen_action)
}

pub fn listen_action(c: &Context) {
    let addr = c.args.first().expect("addr is missing").clone();
    let log = setup_logger("listen.log");
    run(log.clone(), jetsocat::server::listen(addr, log));
}
