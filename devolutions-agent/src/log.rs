use devolutions_log::StaticLogConfig;

pub struct AgentLog;

impl StaticLogConfig for AgentLog {
    const MAX_BYTES_PER_LOG_FILE: u64 = 3_000_000; // 3 MB;
    const MAX_LOG_FILES: usize = 10;
    const LOG_FILE_PREFIX: &'static str = "agent";
}
