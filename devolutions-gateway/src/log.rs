use std::io;
use std::time::SystemTime;

use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::fs;
use tokio::time::{sleep, Duration};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::dto::VerbosityProfile;

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

fn profile_to_directives(profile: VerbosityProfile) -> &'static str {
    match profile {
        VerbosityProfile::Default => "info",
        VerbosityProfile::Debug => {
            "info,devolutions_gateway=debug,devolutions_gateway::api=trace,jmux_proxy=debug,tower_http=trace"
        }
        VerbosityProfile::Tls => {
            "info,devolutions_gateway=debug,devolutions_gateway::tls=trace,rustls=trace,tokio_rustls=debug"
        }
        VerbosityProfile::All => "trace",
        VerbosityProfile::Quiet => "warn",
    }
}

pub fn init(
    path: &Utf8Path,
    profile: VerbosityProfile,
    debug_filtering_directives: Option<&str>,
) -> anyhow::Result<LoggerGuard> {
    let log_cfg = LogPathCfg::from_path(path)?;
    let file_appender = rolling::Builder::new()
        .rotation(rolling::Rotation::max_bytes(MAX_BYTES_PER_LOG_FILE))
        .filename_prefix(log_cfg.prefix)
        .filename_suffix("log")
        .max_log_files(MAX_LOG_FILES)
        .build(log_cfg.folder)
        .context("couldn’t create file appender")?;
    let (file_non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::layer().with_writer(file_non_blocking).with_ansi(false);

    let (non_blocking_stdio, stdio_guard) = tracing_appender::non_blocking(std::io::stdout());
    let stdio_layer = fmt::layer().with_writer(non_blocking_stdio);

    let env_filter = EnvFilter::try_new(profile_to_directives(profile))
        .context("invalid built-in filtering directives (this is a bug)")?;

    // Optionally add additional debugging filtering directives
    let env_filter = debug_filtering_directives
        .into_iter()
        .flat_map(|directives| directives.split(','))
        .fold(env_filter, |env_filter, directive| {
            env_filter.add_directive(directive.parse().unwrap())
        });

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

/// File deletion task (by age)
///
/// Given path is used to filter out by file name prefix.
pub struct LogDeleterTask {
    pub prefix: Utf8PathBuf,
}

#[async_trait]
impl Task for LogDeleterTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "log deleter";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        log_deleter_task(&self.prefix, shutdown_signal).await
    }
}

#[instrument(skip(shutdown_signal))]
async fn log_deleter_task(prefix: &Utf8Path, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
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

        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }
    }

    debug!("Task terminated");

    Ok(())
}
