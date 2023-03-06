use std::io;
use std::time::SystemTime;

use anyhow::Context as _;
use camino::Utf8Path;
use tokio::fs;
use tokio::time::{sleep, Duration};
use tracing::metadata::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

const MAX_BYTES_PER_LOG_FILE: u64 = 3_000_000; // 3 MB
const MAX_LOG_FILES: usize = 10;

pub struct LoggerGuard {
    _file_guard: WorkerGuard,
    _stdio_guard: WorkerGuard,
}

struct LogPathCfg<'a> {
    folder: &'a Utf8Path,
    prefix: &'a str,
}

impl<'a> LogPathCfg<'a> {
    pub fn from_path(path: &'a Utf8Path) -> anyhow::Result<Self> {
        if path.is_dir() {
            Ok(Self {
                folder: path,
                prefix: "gateway",
            })
        } else {
            Ok(Self {
                folder: path.parent().context("invalid log path (parent)")?,
                prefix: path.file_name().context("invalid log path (file_name)")?,
            })
        }
    }
}

pub fn init(path: &Utf8Path, filtering_directive: Option<&str>) -> anyhow::Result<LoggerGuard> {
    let log_cfg = LogPathCfg::from_path(path)?;
    let file_appender = rolling::Builder::new()
        .rotation(rolling::Rotation::max_bytes(MAX_BYTES_PER_LOG_FILE))
        .filename_prefix(log_cfg.prefix)
        .filename_suffix("log")
        .max_log_files(MAX_LOG_FILES)
        .build(log_cfg.folder)
        .context("Couldn’t create file appender")?;
    let (file_non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::layer().with_writer(file_non_blocking).with_ansi(false);

    let (non_blocking_stdio, stdio_guard) = tracing_appender::non_blocking(std::io::stdout());
    let stdio_layer = fmt::layer().with_writer(non_blocking_stdio);

    let default_directive = Directive::from(LevelFilter::INFO);

    let env_filter = if let Some(filtering_directive) = filtering_directive {
        EnvFilter::builder()
            .with_default_directive(default_directive)
            .parse(filtering_directive)
            .context("invalid filtering directive from config")?
    } else {
        EnvFilter::builder()
            .with_default_directive(default_directive)
            .from_env()
            .context("invalid filtering directive from env")?
    };

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stdio_layer)
        .with(env_filter)
        .init();

    Ok(LoggerGuard {
        _file_guard: file_guard,
        _stdio_guard: stdio_guard,
    })
}

/// File deletion task (by age)
///
/// Given path is used to filter out by file name prefix.
#[instrument]
pub async fn log_deleter_task(prefix: &Utf8Path) -> anyhow::Result<()> {
    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24); // once per day
    const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 90); // 90 days

    debug!("Task started");

    let cfg = LogPathCfg::from_path(prefix)?;

    loop {
        match fs::read_dir(cfg.folder).await {
            Ok(mut read_dir) => {
                while let Ok(Some(entry)) = read_dir.next_entry().await {
                    match entry.file_name().to_str() {
                        Some(file_name) if file_name.starts_with(cfg.prefix) && file_name.contains("log") => {
                            debug!(file_name, "Found a log file");
                            match entry
                                .metadata()
                                .await
                                .and_then(|metadata| metadata.modified())
                                .and_then(|time| time.elapsed().map_err(|e| io::Error::new(io::ErrorKind::Other, e)))
                            {
                                Ok(modified) if modified > MAX_AGE => {
                                    info!(file_name, "Delete log file");
                                    if let Err(error) = fs::remove_file(entry.path()).await {
                                        warn!(%error, file_name, "Couldn't delete log file");
                                    }
                                }
                                Ok(_) => {
                                    trace!(file_name, "Keep this log file");
                                }
                                Err(error) => {
                                    warn!(%error, file_name, "Couldn't retrieve metadata for file");
                                }
                            }
                        }
                        _ => continue,
                    }
                }
            }
            Err(error) => {
                warn!(%error, "Couldn't read log folder");
            }
        }

        sleep(TASK_INTERVAL).await;
    }
}

/// Find latest log file (by age)
///
/// Given path is used to filter out by file name prefix.
#[instrument]
pub async fn find_latest_log_file(prefix: &Utf8Path) -> anyhow::Result<std::path::PathBuf> {
    let cfg = LogPathCfg::from_path(prefix)?;

    let mut read_dir = fs::read_dir(cfg.folder).await.context("couldn't read directory")?;

    let mut most_recent_time = SystemTime::UNIX_EPOCH;
    let mut most_recent = None;

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        match entry.file_name().to_str() {
            Some(file_name) if file_name.starts_with(cfg.prefix) && file_name.contains("log") => {
                debug!(file_name, "Found a log file");
                match entry.metadata().await.and_then(|metadata| metadata.modified()) {
                    Ok(modified) if modified > most_recent_time => {
                        most_recent_time = modified;
                        most_recent = Some(entry.path());
                    }
                    Ok(_) => {}
                    Err(error) => {
                        warn!(%error, file_name, "Couldn't retrieve metadata for file");
                    }
                }
            }
            _ => continue,
        }
    }

    most_recent.context("no file found")
}
