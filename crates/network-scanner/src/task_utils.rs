use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::event_bus::EventBus;
use crate::ip_utils::{IpAddrRange, Subnet, get_subnets};
use crate::mdns::MdnsDaemon;
use crate::named_port::MaybeNamedPort;
use crate::scanner::{NetworkScanner, ScannerConfig, ScannerToggles};

#[derive(Debug, Clone)]
pub(crate) struct ContextConfig {
    pub(crate) broadcast_subnet: Vec<Subnet>, // The subnet that have a broadcast address
    pub(crate) range_to_ping: Vec<IpAddrRange>,
    pub ports: Vec<MaybeNamedPort>,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub broadcast_timeout: Duration,
    pub port_scan_timeout: Duration,
    pub netbios_timeout: Duration,
    pub netbios_interval: Duration,
    pub mdns_query_timeout: Duration,
}

impl ContextConfig {
    pub(crate) fn new(
        ScannerConfig {
            broadcast_timeout,
            mdns_query_timeout,
            netbios_timeout,
            netbios_interval,
            ping_timeout,
            ping_interval,
            port_scan_timeout,
            ports,
            ip_ranges,
            ..
        }: ScannerConfig,
        toggles: &ScannerToggles,
        subnet: Vec<Subnet>,
    ) -> Self {
        let range_to_ping = match ip_ranges.len() {
            0 if toggles.enable_subnet_scan => subnet.iter().map(IpAddrRange::from).collect::<Vec<IpAddrRange>>(),
            _ => ip_ranges,
        };

        Self {
            broadcast_subnet: subnet,
            range_to_ping,
            ports,
            ping_interval,
            ping_timeout,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            netbios_interval,
            mdns_query_timeout,
        }
    }
}

#[derive(Clone)]
pub(crate) struct TaskExecutionContext {
    pub(crate) event_bus: EventBus,

    pub(crate) ip_cache: Arc<parking_lot::RwLock<HashMap<IpAddr, Option<String>>>>,

    pub(crate) runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    pub(crate) mdns_daemon: Option<MdnsDaemon>,

    pub(crate) configs: ContextConfig,
    pub(crate) toggles: ScannerToggles,
}

type HandlesReceiver = crossbeam::channel::Receiver<tokio::task::JoinHandle<anyhow::Result<()>>>;
type HandlesSender = crossbeam::channel::Sender<tokio::task::JoinHandle<anyhow::Result<()>>>;

impl TaskExecutionContext {
    pub(crate) fn new(network_scanner: NetworkScanner) -> anyhow::Result<Self> {
        // Since the boarcast receiver does not implement Clone, we'll subscribe to the channel using the sender when we need it
        let event_bus = EventBus::new();

        let NetworkScanner {
            mdns_daemon,
            runtime,
            config: configs,
            toggle: toggles,
            ..
        } = network_scanner;

        let broadcast_subnet = get_subnets()?;
        let context = Self {
            event_bus,
            ip_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            runtime,
            mdns_daemon,
            configs: ContextConfig::new(configs, &toggles, broadcast_subnet),
            toggles,
        };

        Ok(context)
    }
}

pub(crate) struct TaskExecutionRunner {
    pub(crate) context: TaskExecutionContext,
    pub(crate) task_manager: TaskManager,
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
        let context = TaskExecutionContext::new(scanner)?;
        Ok(Self {
            context,
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
        let handles = Arc::clone(&self.handles_receiver);
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
