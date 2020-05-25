use chrono::Local;
use slog::{o, Drain, Duplicate, FilterLevel, Level, Logger, Never, OwnedKVList, Record};
use slog_async::{Async, OverflowStrategy};
use slog_term::{Decorator, FullFormat, PlainDecorator, TermDecorator};
use std::{env, fs::OpenOptions, io, result::Result};

const LOGGER_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S:%6f";
const DEFAULT_CHAN_SIZE: usize = 128;

fn format_decorator(decorator: impl Decorator) -> FullFormat<impl Decorator> {
    FullFormat::new(decorator)
        .use_custom_timestamp(|output: &mut dyn io::Write| -> io::Result<()> {
            write!(output, "{}", Local::now().format(LOGGER_TIMESTAMP_FORMAT))
        })
        .build()
}

#[derive(Debug, Clone)]
enum OrDrain<D1: Drain<Ok = (), Err = Never>, D2: Drain<Ok = (), Err = Never>> {
    A(D1),
    B(D2),
}

impl<D1: Drain<Ok = (), Err = Never>, D2: Drain<Ok = (), Err = Never>> Drain for OrDrain<D1, D2> {
    type Ok = ();
    type Err = Never;

    fn log(&self, record: &Record, logger_values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        match self {
            OrDrain::A(drain) => drain.log(record, logger_values),
            OrDrain::B(drain) => drain.log(record, logger_values),
        }
    }

    fn is_enabled(&self, level: Level) -> bool {
        match self {
            OrDrain::A(drain) => drain.is_enabled(level),
            OrDrain::B(drain) => drain.is_enabled(level),
        }
    }
}

pub fn init(file_path: Option<&String>) -> io::Result<Logger> {
    let term_decorator = TermDecorator::new().build();
    let term_fmt = format_decorator(term_decorator);

    let drain_decorator = if let Some(file_path) = file_path {
        let outfile = OpenOptions::new().create(true).append(true).open(file_path)?;
        let file_decorator = PlainDecorator::new(outfile);
        let file_fmt = format_decorator(file_decorator);

        OrDrain::A(Duplicate(file_fmt, term_fmt).fuse())
    } else {
        OrDrain::B(term_fmt.fuse())
    };

    let env_drain = slog_envlogger::LogBuilder::new(drain_decorator)
        .filter(None, FilterLevel::Info)
        .parse(env::var("RUST_LOG").unwrap_or(String::new()).as_str())
        .build();

    let drain = Async::new(env_drain.fuse())
        .chan_size(DEFAULT_CHAN_SIZE)
        .overflow_strategy(OverflowStrategy::DropAndReport)
        .build()
        .fuse();

    let logger = Logger::root(
        drain,
        o!("module" => slog::FnValue(move |info| {
            format!("[{}]", info.module())
        })),
    );

    Ok(logger)
}
