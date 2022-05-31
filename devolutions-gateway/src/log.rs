use std::io;
use std::time::SystemTime;

use anyhow::Context as _;
use camino::Utf8Path;
use tokio::fs;
use tokio::time::{sleep, Duration};
use tracing::metadata::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

pub struct LoggerGuard {
    _file_guard: Option<WorkerGuard>,
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
                prefix: "gateway.log",
            })
        } else {
            Ok(Self {
                folder: path.parent().context("invalid log path (parent)")?,
                prefix: path.file_name().context("invalid log path (file_name)")?,
            })
        }
    }
}

pub fn init(path: Option<&Utf8Path>, filtering_directive: Option<&str>) -> anyhow::Result<LoggerGuard> {
    let (file_layer, file_guard) = if let Some(path) = path {
        let cfg = LogPathCfg::from_path(path)?;

        let file_appender = tracing_appender::rolling::daily(cfg.folder, cfg.prefix);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);

        (Some(file_layer), Some(guard))
    } else {
        (None, None)
    };

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
    const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 10); // 10 days

    debug!("Task started");

    let cfg = LogPathCfg::from_path(prefix)?;

    loop {
        match fs::read_dir(cfg.folder).await {
            Ok(mut read_dir) => {
                while let Ok(Some(entry)) = read_dir.next_entry().await {
                    match entry.file_name().to_str() {
                        Some(file_name) if file_name.starts_with(cfg.prefix) => {
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
                                    debug!(file_name, "Keep this log file");
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
            Some(file_name) if file_name.starts_with(cfg.prefix) => {
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
