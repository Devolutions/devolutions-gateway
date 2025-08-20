use std::sync::LazyLock;

use tokio::sync::{Mutex, RwLock};

use network_scanner_net::runtime::Socket2Runtime;

use crate::log_queue::*;
use crate::*;

pub struct State {
    pub(crate) cache_path: Utf8PathBuf,
    pub(crate) log: LogQueue<MonitorResult>,
    pub(crate) config: RwLock<MonitorsConfig>,
    pub(crate) cancellation_tokens: Mutex<HashMap<String, CancellationToken>>,
    pub(crate) scanner_runtime: LazyLock<anyhow::Result<Arc<Socket2Runtime>>>,
}

impl State {
    pub fn new(cache_path: Utf8PathBuf) -> State {
        State {
            cache_path: cache_path,
            log: LogQueue::new(),
            config: RwLock::new(MonitorsConfig::empty()),
            cancellation_tokens: Mutex::new(HashMap::new()),
            scanner_runtime: LazyLock::new(|| Socket2Runtime::new(None)),
        }
    }

    pub fn mock(cache_path: Utf8PathBuf) -> State {
        State {
            cache_path: cache_path,
            log: LogQueue::new(),
            config: RwLock::new(MonitorsConfig::mock()),
            cancellation_tokens: Mutex::new(HashMap::new()),
            scanner_runtime: LazyLock::new(|| Socket2Runtime::new(None)),
        }
    }
}
