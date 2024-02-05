use std::{net::IpAddr, sync::Arc, time::Duration};

use dashmap::DashMap;

use futures::Future;
use tokio::sync::Mutex;

use crate::{
    ip_utils::{get_subnets, Subnet},
    scanner::NetworkScanner,
};

type IpSender = tokio::sync::mpsc::Sender<(IpAddr, Option<String>)>;
type IpReceiver = tokio::sync::mpsc::Receiver<(IpAddr, Option<String>)>;
type PortSender = tokio::sync::mpsc::Sender<(IpAddr, Option<String>, u16)>;
type PortReceiver = tokio::sync::mpsc::Receiver<(IpAddr, Option<String>, u16)>;
#[derive(Debug, Clone)]
pub(crate) struct TaskExecutionContext {
    pub handles_sender: HandlesSender,
    pub ip_sender: IpSender,
    pub ip_receiver: Arc<Mutex<IpReceiver>>,

    pub port_sender: PortSender,
    pub port_receiver: Arc<Mutex<PortReceiver>>,

    pub ip_cache: Arc<DashMap<IpAddr, Option<String>>>,
    pub ports: Vec<u16>,

    pub runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    pub ping_interval: Duration,     // in milliseconds
    pub ping_timeout: Duration,      // in milliseconds
    pub broadcast_timeout: Duration, // in milliseconds
    pub port_scan_timeout: Duration, // in milliseconds
    pub netbios_timeout: Duration,   // in milliseconds
    pub subnets: Vec<Subnet>,
}

type HandlesReceiver = crossbeam::channel::Receiver<tokio::task::JoinHandle<anyhow::Result<()>>>;
type HandlesSender = crossbeam::channel::Sender<tokio::task::JoinHandle<anyhow::Result<()>>>;
#[derive(Debug)]
pub(crate) struct TaskExecutionRunner {
    pub(crate) context: TaskExecutionContext,
    pub(crate) handles_receiver: HandlesReceiver,
    pub(crate) handles_sender: HandlesSender,
}

impl TaskExecutionContext {
    pub(crate) fn new(network_scanner: NetworkScanner, handles_sender: HandlesSender) -> anyhow::Result<Self> {
        let (ip_sender, ip_receiver) = tokio::sync::mpsc::channel(1024);
        let ip_receiver = Arc::new(Mutex::new(ip_receiver));

        let (port_sender, port_receiver) = tokio::sync::mpsc::channel(1024);
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
            ..
        } = network_scanner;

        let res = Self {
            handles_sender,
            ip_sender,
            ip_receiver,
            port_sender,
            port_receiver,
            ip_cache: Arc::new(DashMap::new()),
            ports,
            runtime,
            ping_interval,
            ping_timeout,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            subnets,
        };

        Ok(res)
    }
}

impl TaskExecutionRunner {
    // Move the generic parameters to the method level.
    pub(crate) fn run<T, F>(&mut self, task: T)
    where
        T: FnOnce(TaskExecutionContext) -> F + Send + 'static,
        F: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let context = self.context.clone();
        let handle = tokio::task::spawn(async move { task(context).await });
        let _ = self.handles_sender.send(handle);
    }

    pub(crate) fn new(scanner: NetworkScanner) -> anyhow::Result<Self> {
        let (handles_sender, handles_receiver) = crossbeam::channel::unbounded();
        Ok(Self {
            context: TaskExecutionContext::new(scanner, handles_sender.clone())?,
            handles_receiver,
            handles_sender,
        })
    }
}
