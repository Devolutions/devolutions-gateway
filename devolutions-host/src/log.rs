use crate::config::ConfHandle;
use devolutions_log::{LoggerGuard, StaticLogConfig};

pub(crate) struct HostLog;

impl StaticLogConfig for HostLog {
    const MAX_BYTES_PER_LOG_FILE: u64 = 3_000_000; // 3 MB;
    const MAX_LOG_FILES: usize = 10;
    const LOG_FILE_PREFIX: &'static str = "host";
}

pub fn init_log(config: ConfHandle) -> LoggerGuard {
    let conf = config.get_conf();

    devolutions_log::init::<HostLog>(
        &conf.log_file,
        conf.verbosity_profile.to_log_filter(),
        conf.debug.log_directives.as_deref(),
    )
    .expect("BUG: Failed to initialize log")
}
