use tokio::sync::{Mutex, RwLock};

use crate::log_queue::*;
use crate::*;

pub struct State {
    pub(crate) log: LogQueue<MonitorResult>,
    pub(crate) config: RwLock<MonitorsConfig>,
    pub(crate) cancellation_tokens: Mutex<HashMap<String, CancellationToken>>
}

impl State {
    pub(crate) fn mock() -> State {
        State {
            log: LogQueue::new(),
            config: RwLock::new(MonitorsConfig::mock()),
            cancellation_tokens: Mutex::new(HashMap::new())
        }
    }
}