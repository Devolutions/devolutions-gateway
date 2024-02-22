use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use std::future::Future;

use tokio::sync::Mutex;

use crate::ip_utils::{get_subnets, Subnet};
use crate::mdns::MdnsDaemon;
use crate::scanner::{NetworkScanner, ScanEntry};

pub(crate) type IpSender = tokio::sync::mpsc::Sender<(IpAddr, Option<String>)>;
pub(crate) type IpReceiver = tokio::sync::mpsc::Receiver<(IpAddr, Option<String>)>;
pub(crate) type ScanEntrySender = tokio::sync::mpsc::Sender<ScanEntry>;
pub(crate) type ScanEntryReceiver = tokio::sync::mpsc::Receiver<ScanEntry>;

#[derive(Clone)]
pub(crate) struct TaskExecutionContext {
    pub ip_sender: IpSender,
    pub ip_receiver: Arc<Mutex<IpReceiver>>,

    pub port_sender: ScanEntrySender,
    pub port_receiver: Arc<Mutex<ScanEntryReceiver>>,

    pub ip_cache: Arc<parking_lot::RwLock<HashMap<IpAddr, Option<String>>>>,

    pub ports: Vec<u16>,

    pub runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    pub mdns_daemon: MdnsDaemon,

    pub ping_interval: Duration,      // in milliseconds
    pub ping_timeout: Duration,       // in milliseconds
    pub broadcast_timeout: Duration,  // in milliseconds
    pub port_scan_timeout: Duration,  // in milliseconds
    pub netbios_timeout: Duration,    // in milliseconds
    pub netbios_interval: Duration,   // in milliseconds
    pub mdns_query_timeout: Duration, // in milliseconds

    pub subnets: Vec<Subnet>,
}

type HandlesReceiver = crossbeam::channel::Receiver<tokio::task::JoinHandle<anyhow::Result<()>>>;
type HandlesSender = crossbeam::channel::Sender<tokio::task::JoinHandle<anyhow::Result<()>>>;

pub(crate) struct TaskExecutionRunner {
    pub(crate) context: TaskExecutionContext,
    pub(crate) task_manager: TaskManager,
}

impl TaskExecutionContext {
    pub(crate) fn new(network_scanner: NetworkScanner) -> anyhow::Result<Self> {
        let (ip_sender, ip_receiver) = tokio::sync::mpsc::channel(5);
        let ip_receiver = Arc::new(Mutex::new(ip_receiver));

        let (port_sender, port_receiver) = tokio::sync::mpsc::channel(100);
        let port_receiver = Arc::new(Mutex::new(port_receiver));

        let subnets = get_subnets()?;
        let NetworkScanner {
            ports,
            ping_timeout,
            ping_interval,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            runtime,
            netbios_interval,
            mdns_daemon,
            mdns_query_timeout,
            ..
        } = network_scanner;

        let res = Self {
            ip_sender,
            ip_receiver,
            port_sender,
            port_receiver,
            ip_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            ports,
            runtime,
            mdns_daemon,
            ping_interval,
            ping_timeout,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            netbios_interval,
            subnets,
            mdns_query_timeout,
        };

        Ok(res)
    }
}

impl TaskExecutionRunner {
    pub(crate) fn run<T, F>(&mut self, task: T)
    where
        T: FnOnce(TaskExecutionContext, TaskManager) -> F + Send + 'static,
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let context = self.context.clone();
        self.task_manager
            .spawn_no_sub_task(task(context, self.task_manager.clone()));
    }

    pub(crate) fn new(scanner: NetworkScanner) -> anyhow::Result<Self> {
        Ok(Self {
            context: TaskExecutionContext::new(scanner)?,
            task_manager: TaskManager::new(),
        })
    }
}

/// A task manager that can spawn tasks and stop them.
/// Collects all the handles of the spawned tasks and stops them when the stop method is called.
/// Helps to manage the lifetime of the spawned tasks.
#[derive(Debug, Clone)]
pub struct TaskManager {
    handles_sender: HandlesSender,
    handles_receiver: Arc<HandlesReceiver>,
    should_stop: Arc<AtomicBool>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        // This channel needs to be unbounded. Because we only clear out the channel once when we stop the tasks.
        // If the channel is bounded, all tokio workers will be blocked forever and eventually the program will hang.
        let (handles_sender, handles_receiver) = crossbeam::channel::unbounded();
        Self {
            handles_sender,
            handles_receiver: Arc::new(handles_receiver),
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn spawn<T, F>(&self, task: T)
    where
        T: FnOnce(Self) -> F + Send + 'static,
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        // Avoid race condition when stopping the tasks.
        // If the stop method is called, we should not spawn any more tasks.
        if self.should_stop.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let clone = self.clone();
        let handle = tokio::spawn(task(clone));
        let _ = self.handles_sender.send(handle);
    }

    pub(crate) fn spawn_no_sub_task<F>(&self, task: F)
    where
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.spawn(|_| task);
    }

    pub(crate) fn with_timeout(&self, duration: Duration) -> TimeoutManager {
        TimeoutManager {
            task_manager: self.clone(),
            duration,
            when_finish: None,
        }
    }

    pub(crate) fn stop(&self) {
        self.should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let handles = self.handles_receiver.clone();
        while let Ok(handle) = handles.try_recv() {
            handle.abort();
        }
        debug!("All tasks stopped");
    }
}

pub(crate) struct TimeoutManager {
    task_manager: TaskManager,
    duration: Duration,
    when_finish: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl TimeoutManager {
    pub(crate) fn when_finish<F>(self, f: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let Self {
            task_manager, duration, ..
        } = self;

        let when_finish = Some(Box::new(f) as Box<dyn FnOnce() + Send + 'static>);

        Self {
            task_manager,
            duration,
            when_finish,
        }
    }

    pub(crate) fn spawn<T, F>(self, task: T)
    where
        T: FnOnce(TaskManager) -> F + Send + 'static,
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let Self {
            task_manager,
            duration,
            when_finish,
        } = self;

        task_manager.spawn(move |task_manager| async move {
            let future = task(task_manager);
            let _ = tokio::time::timeout(duration, future).await;
            if let Some(when_finish) = when_finish {
                when_finish();
            }
            anyhow::Ok(())
        });
    }
}
