use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Context as _;
use network_scanner_net::runtime::Socket2Runtime;
use tokio_util::sync::CancellationToken;

use crate::log_queue::LogQueue;
use crate::{MonitorId, MonitorResult, MonitorsConfig};

pub trait ConfigCache: Send + Sync {
    fn store(&self, new_config: &MonitorsConfig) -> anyhow::Result<()>;
}

pub struct State {
    pub(crate) config_cache: Arc<dyn ConfigCache>,
    pub(crate) log: LogQueue<MonitorResult>,
    pub(crate) config: RwLock<MonitorsConfig>,
    pub(crate) cancellation_tokens: Mutex<HashMap<MonitorId, CancellationToken>>,
    pub(crate) scanner_runtime: Arc<Socket2Runtime>,

    /// A 1-permit semaphore to be used in the set_config function.
    ///
    /// This is used to make sure there is no race condition such as:
    ///
    /// - Call set_config, and start cancelling / starting monitoring tasks
    /// - Call set_config before the adjustements from the previous call are terminated
    ///
    /// Most likely, nothing bad happens, but it’s hard to be sure that the current (or future) code
    /// is written in a way that is resistent to concurrent execution.
    ///
    /// INVARIANT: This semaphore is never closed.
    pub(crate) set_config_permit: tokio::sync::Semaphore,
}

impl State {
    pub fn new(config_cache: Arc<dyn ConfigCache>) -> anyhow::Result<State> {
        let scanner_runtime = Socket2Runtime::new(None).context("create socket2 runtime")?;

        let state = State {
            config_cache,
            log: LogQueue::new(),
            config: RwLock::new(MonitorsConfig::empty()),
            cancellation_tokens: Mutex::new(HashMap::new()),
            scanner_runtime,
            set_config_permit: tokio::sync::Semaphore::new(1),
        };

        Ok(state)
    }
}
