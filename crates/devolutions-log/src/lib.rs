#[macro_use]
extern crate tracing;

use std::io;
use std::time::SystemTime;

use anyhow::Context as _;
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::fs;
use tokio::time::{Duration, sleep};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

pub trait StaticLogConfig {
    const MAX_BYTES_PER_LOG_FILE: u64;
    const MAX_LOG_FILES: usize;
    const LOG_FILE_PREFIX: &'static str;
}

/// Metadata for a retained log file in the configured log directory.
pub struct LogFile {
    pub path: std::path::PathBuf,
    pub name: String,
    pub size: u64,
    pub modified: SystemTime,
}

pub struct LoggerGuard {
    _file_guard: WorkerGuard,
    _stdio_guard: WorkerGuard,
}

struct LogPathCfg<'a, C: StaticLogConfig> {
    folder: &'a Utf8Path,
    prefix: &'a str,
    _phantom: std::marker::PhantomData<C>,
}

impl<'a, C: StaticLogConfig> LogPathCfg<'a, C> {
    pub(crate) fn from_path(path: &'a Utf8Path) -> anyhow::Result<Self> {
        if path.is_dir() {
            Ok(Self {
                folder: path,
                prefix: C::LOG_FILE_PREFIX,
                _phantom: std::marker::PhantomData,
            })
        } else {
            Ok(Self {
                folder: path.parent().context("invalid log path (parent)")?,
                prefix: path.file_name().context("invalid log path (file_name)")?,
                _phantom: std::marker::PhantomData,
            })
        }
    }
}

pub fn init<C: StaticLogConfig>(
    path: &Utf8Path,
    log_filter: &str,
    debug_filtering_directives: Option<&str>,
) -> anyhow::Result<LoggerGuard> {
    let log_cfg = LogPathCfg::<C>::from_path(path)?;
    let file_appender = rolling::Builder::new()
        .rotation(rolling::Rotation::max_bytes(C::MAX_BYTES_PER_LOG_FILE))
        .filename_prefix(log_cfg.prefix)
        .filename_suffix("log")
        .max_log_files(C::MAX_LOG_FILES)
        .build(log_cfg.folder)
        .context("couldn’t create file appender")?;
    let (file_non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::layer().with_writer(file_non_blocking).with_ansi(false);

    let (non_blocking_stdio, stdio_guard) = tracing_appender::non_blocking(io::stdout()); // FIXME: Should be to stderr.
    let stdio_layer = fmt::layer().with_writer(non_blocking_stdio);

    let env_filter = EnvFilter::try_new(log_filter).context("invalid built-in filtering directives (this is a bug)")?;

    // Optionally add additional debugging filtering directives
    let env_filter = debug_filtering_directives
        .into_iter()
        .flat_map(|directives| directives.split(','))
        .fold(env_filter, |env_filter, directive| {
            env_filter.add_directive(directive.parse().expect("a valid log directive (debug option)"))
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

/// Finds the newest retained regular log file by modification time.
///
/// Uses the same file filter and order as [`list_log_files`].
#[instrument]
pub async fn find_latest_log_file<C: StaticLogConfig>(prefix: &Utf8Path) -> anyhow::Result<std::path::PathBuf> {
    list_log_files::<C>(prefix)
        .await?
        .into_iter()
        .next()
        .map(|file| file.path)
        .context("no file found")
}

/// Lists the regular log files retained under the configured log path.
pub async fn list_log_files<C: StaticLogConfig>(path: &Utf8Path) -> anyhow::Result<Vec<LogFile>> {
    let cfg = LogPathCfg::<C>::from_path(path)?;
    let mut read_dir = fs::read_dir(cfg.folder).await.context("couldn't read log directory")?;
    let mut files = Vec::new();

    while let Some(entry) = read_dir.next_entry().await.context("couldn't read log entry")? {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };

        if !name.starts_with(cfg.prefix) || !name.ends_with(".log") {
            continue;
        }

        let file_type = match entry.file_type().await {
            Ok(file_type) => file_type,
            Err(error) => {
                warn!(%error, name, "Couldn't read log file type");
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }

        let metadata = match entry.metadata().await {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(%error, name, "Couldn't read log metadata");
                continue;
            }
        };
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(error) => {
                warn!(%error, name, "Couldn't read log modification time");
                continue;
            }
        };
        files.push(LogFile {
            path: entry.path(),
            name,
            size: metadata.len(),
            modified,
        });
    }

    files.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| compare_log_file_names(&right.name, &left.name))
    });
    Ok(files)
}

fn compare_log_file_names(left: &str, right: &str) -> std::cmp::Ordering {
    let rotations = left
        .strip_suffix(".log")
        .and_then(|name| name.rsplit_once('.'))
        .zip(right.strip_suffix(".log").and_then(|name| name.rsplit_once('.')));

    if let Some(((left_base, left_rotation), (right_base, right_rotation))) = rotations
        && left_base == right_base
        && let (Ok(left_rotation), Ok(right_rotation)) = (left_rotation.parse::<u64>(), right_rotation.parse::<u64>())
    {
        return left_rotation.cmp(&right_rotation).then_with(|| left.cmp(right));
    }

    left.cmp(right)
}

/// File deletion task (by age)
///
/// Given path is used to filter out by file name prefix.
pub struct LogDeleterTask<C: StaticLogConfig> {
    path: Utf8PathBuf,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: StaticLogConfig> LogDeleterTask<C> {
    pub fn new(path: Utf8PathBuf) -> Self {
        Self {
            path,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<C: StaticLogConfig + Send> Task for LogDeleterTask<C> {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "log deleter";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        log_deleter_task::<C>(&self.path, shutdown_signal).await
    }
}

#[instrument(skip(shutdown_signal))]
async fn log_deleter_task<C: StaticLogConfig>(
    path: &Utf8Path,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24); // once per day
    const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 90); // 90 days

    debug!("Task started");

    let cfg = LogPathCfg::<C>::from_path(path)?;

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
                                .and_then(|time| time.elapsed().map_err(io::Error::other))
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
