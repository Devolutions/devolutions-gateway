use std::{env, fs::OpenOptions, io, result::Result, str::FromStr};

use chrono::Utc;
use slog::{o, warn, Drain, Duplicate, Level, LevelFilter, Logger};
use slog_async::Async;
use slog_term::{Decorator, FullFormat, PlainDecorator, TermDecorator};

const LOGGER_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S:%6f";
const DEFAULT_LOG_LEVEL: Level = Level::Info;

fn format_decorator(decorator: impl Decorator) -> FullFormat<impl Decorator> {
    FullFormat::new(decorator)
        .use_custom_timestamp(|output: &mut dyn io::Write| -> io::Result<()> {
            write!(output, "{}", Utc::now().format(LOGGER_TIMESTAMP_FORMAT))
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

    let term_decorator = TermDecorator::new().build();
    let term_fmt = format_decorator(term_decorator).fuse();
    let term_drain = LevelFilter::new(term_fmt, log_level).fuse();

    let drain = if let Some(file_path) = file_path {
        let outfile = OpenOptions::new().create(true).append(true).open(file_path)?;
        let file_decorator = PlainDecorator::new(outfile);
        let file_fmt = format_decorator(file_decorator).fuse();
        let file_drain = LevelFilter::new(file_fmt, log_level).fuse();

        Async::new(Duplicate(file_drain, term_drain).fuse()).build().fuse()
    } else {
        Async::new(term_drain).build().fuse()
    };
    let logger = Logger::root(drain, o!());

    if log_level_result.is_err() {
        warn!(logger, "RUST_LOG value was invalid, setting to the default value: INFO");
    }

    Ok(logger)
}
