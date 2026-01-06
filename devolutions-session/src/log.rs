use devolutions_log::{LoggerGuard, StaticLogConfig};

use crate::config::Conf;

pub(crate) struct SessionLog;

impl StaticLogConfig for SessionLog {
    const MAX_BYTES_PER_LOG_FILE: u64 = 3_000_000; // 3 MB;
    const MAX_LOG_FILES: usize = 10;
    const LOG_FILE_PREFIX: &'static str = "session";
}

pub fn init_log(conf: &Conf) -> LoggerGuard {
    devolutions_log::init::<SessionLog>(
        &conf.log_file,
        conf.verbosity_profile.to_log_filter(),
        conf.debug.log_directives.as_deref(),
    )
    .expect("BUG: Failed to initialize log")
}
