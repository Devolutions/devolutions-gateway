use std::{env, fs::OpenOptions, io, result::Result, str::FromStr};

use chrono::Local;
use slog::{o, warn, Drain, Duplicate, Level, LevelFilter, Logger};
use slog_async::{Async, OverflowStrategy};
use slog_term::{Decorator, FullFormat, PlainDecorator, TermDecorator};

const LOGGER_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S:%6f";
const DEFAULT_LOG_LEVEL: Level = Level::Info;
const DEFAULT_CHAN_SIZE: usize = 128;
const DEBUG_CHAN_SIZE: usize = 256;

fn format_decorator(decorator: impl Decorator) -> FullFormat<impl Decorator> {
    FullFormat::new(decorator)
        .use_custom_timestamp(|output: &mut dyn io::Write| -> io::Result<()> {
            write!(output, "{}", Local::now().format(LOGGER_TIMESTAMP_FORMAT))
        })
        .build()
}

fn rust_log() -> Option<Result<Level, ()>> {
    if let Ok(rust_log) = env::var("RUST_LOG") {
        Some(Level::from_str(rust_log.as_str()))
    } else {
        None
    }
}

pub fn init(file_path: Option<&String>) -> io::Result<Logger> {
    let log_level_result = rust_log().unwrap_or(Ok(DEFAULT_LOG_LEVEL));
    let log_level = log_level_result.unwrap_or(DEFAULT_LOG_LEVEL);

    let (chan_size, overflow_strategy) = if log_level > Level::Info {
        (DEBUG_CHAN_SIZE, OverflowStrategy::Block)
    } else {
        (DEFAULT_CHAN_SIZE, OverflowStrategy::DropAndReport)
    };

    let term_decorator = TermDecorator::new().build();
    let term_fmt = format_decorator(term_decorator).fuse();

    let async_drain = if let Some(file_path) = file_path {
        let outfile = OpenOptions::new().create(true).append(true).open(file_path)?;
        let file_decorator = PlainDecorator::new(outfile);
        let file_fmt = format_decorator(file_decorator).fuse();

        Async::new(Duplicate(file_fmt, term_fmt).fuse())
            .chan_size(chan_size)
            .overflow_strategy(overflow_strategy)
            .build()
            .fuse()
    } else {
        Async::new(term_fmt)
            .chan_size(chan_size)
            .overflow_strategy(overflow_strategy)
            .build()
            .fuse()
    };
    let drain = LevelFilter::new(async_drain, log_level).fuse();
    let logger = Logger::root(
        drain,
        o!("module" => slog::FnValue(move |info| {
            format!("[{}]", info.module())
        })),
    );

    if log_level_result.is_err() {
        warn!(
            logger,
            "RUST_LOG value was invalid, setting to the default value: {:?}", DEFAULT_LOG_LEVEL
        );
    }

    Ok(logger)
}
