use crate::{
    ip_utils::IpAddrRange,
    netbios::netbios_query_scan,
    ping::ping_range,
    port_discovery::{scan_ports, PortScanResult},
    task_utils::{clone2, clone3, clone4, clone5},
    Ok,
};

use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::IpAddr, sync::Arc, time::Duration};

use tokio::{spawn, sync::Mutex, task::spawn_blocking};

use crate::{
    broadcast::asynchronous::broadcast,
    task_utils::{TaskExecutionContext, TaskExecutionRunner},
};

#[derive(Debug, Clone)]
pub struct NetworkScanner {
    pub ports: Vec<u16>,

    pub(crate) runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    // TODO: use this
    // scan_method: Vec<ScanMethod>,
    pub ping_interval: Duration,     // in milliseconds
    pub ping_timeout: Duration,      // in milliseconds
    pub broadcast_timeout: Duration, // in milliseconds
    pub port_scan_timeout: Duration, // in milliseconds
    pub netbios_timeout: Duration,   // in milliseconds
    pub max_wait_time: Duration,     // max_wait for entire scan duration in milliseconds, suggested!
}

impl NetworkScanner {
    pub fn start(&self) -> anyhow::Result<Arc<NetworkScannerStream>> {
        let mut task_executor = TaskExecutionRunner::new(self.clone())?;

        task_executor.run(move |context| async move {
            let TaskExecutionContext {
                ip_cache,
                ip_receiver,
                ports,
                runtime,
                port_scan_timeout,
                port_sender,
                ..
            } = context;
            let ip_cache = ip_cache.clone();
            while let Some((ip, host)) = ip_receiver.lock().await.recv().await {
                if let Some(existed_host) = ip_cache.get(&ip).as_deref() {
                    tracing::info!("IP: {:?} already in cache", ip);
                    // if ip is already in the cache and dns name is resolved, skip
                    if existed_host.is_some() {
                        continue;
                    }

                    if host.is_none() {
                        continue;
                    }
                    // if ip is already in the cache and dns name is not resolved, update the cache and continue
                    ip_cache.insert(ip, host);
                } else {
                    // if ip is not in the cache, add it to the cache and continue
                    ip_cache.insert(ip, host);
                }

                let (runtime, ports, port_scan_timeout, port_sender, ip_cache) =
                    clone5(&runtime, &ports, &port_scan_timeout, &port_sender, &ip_cache);

                spawn(async move {
                    let mut port_scan_receiver = scan_ports(ip, &ports, runtime, port_scan_timeout).await?;
                    tracing::debug!("Scanning ports for ip: {:?}", ip);
                    while let Some(res) = port_scan_receiver.recv().await {
                        if let PortScanResult::Open(socket_addr) = res {
                            let dns = ip_cache.get(&ip).as_deref().cloned().flatten();
                            port_sender.send((ip, dns, socket_addr.port())).await?;
                        }
                    }
                    Ok!()
                });
            }

            Ok!()
        });

        task_executor.run(move |context| async move {
            let TaskExecutionContext {
                subnets,
                broadcast_timeout,
                runtime,
                handles_sender,
                ip_sender,
                ..
            } = context;

            for subnet in subnets {
                let (runtime, ip_sender) = clone2(&runtime, &ip_sender);
                let handler = spawn(async move {
                    let mut receiver = broadcast(subnet.broadcast, broadcast_timeout, runtime).await?;
                    while let Some(ip) = receiver.recv().await {
                        ip_sender.send((ip.into(), None)).await?;
                    }
                    Ok!()
                });

                handles_sender.send(handler)?;
            }
            Ok!()
        });

        task_executor.run(move |context| async move {
            let TaskExecutionContext {
                subnets,
                netbios_timeout,
                runtime,
                ip_sender,
                ..
            } = context;

            let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();

            for ip_range in ip_ranges {
                // let (runtime,netbios_timeout) = clone2(&runtime, &netbios_timeout);
                let (runtime, netbios_timeout, ip_sender) = clone3(&runtime, &netbios_timeout, &ip_sender);
                let mut receiver = netbios_query_scan(runtime, ip_range, netbios_timeout, Duration::from_millis(20))?;
                while let Some((ip, name)) = receiver.recv().await {
                    ip_sender.send((ip.into(), Some(name))).await?;
                }
            }
            Ok!()
        });

        task_executor.run(move |context| async move {
            let TaskExecutionContext {
                ping_interval,
                ping_timeout,
                runtime,
                ip_sender,
                subnets,
                ip_cache,
                ..
            } = context;

            let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();

            let should_ping = move |ip: IpAddr| -> bool { !ip_cache.contains_key(&ip) };

            for ip_range in ip_ranges {
                let (runtime, ping_interval, ping_timeout, ip_sender) =
                    clone4(&runtime, &ping_interval, &ping_timeout, &ip_sender);
                let should_ping = should_ping.clone();
                let mut receiver = ping_range(runtime, ip_range, ping_interval, ping_timeout, should_ping)?;

                while let Some(ip) = receiver.recv().await {
                    ip_sender.send((ip, None)).await?;
                }
            }
            Ok!()
        });

        let TaskExecutionRunner {
            handles_receiver,
            context: TaskExecutionContext { port_receiver, .. },
            ..
        } = task_executor;

        let max_wait_time = self.max_wait_time;
        let handles_receiver_clone = handles_receiver.clone();
        spawn_blocking(move || {
            std::thread::sleep(max_wait_time);
            while let Ok(handle) = handles_receiver_clone.recv() {
                handle.abort();
            }
        });

        Ok({
            Arc::new(NetworkScannerStream {
                result_receiver: port_receiver,
                task_handles: handles_receiver,
            })
        })
    }

    pub fn new(params: NetworkScannerParams) -> anyhow::Result<Self> {
        let NetworkScannerParams {
            ports,
            ping_timeout,
            max_wait_time: max_wait,
            ping_interval,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
        } = params;

        let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

        let ping_timeout = Duration::from_millis(ping_timeout.unwrap_or(100));
        let ping_interval = Duration::from_millis(ping_interval.unwrap_or(500));
        let broadcast_timeout = Duration::from_millis(broadcast_timeout.unwrap_or(1000));
        let port_scan_timeout = Duration::from_millis(port_scan_timeout.unwrap_or(1000));
        let netbios_timeout = Duration::from_millis(netbios_timeout.unwrap_or(1000));
        let max_wait = Duration::from_millis(max_wait.unwrap_or(10 * 1000)); //10 seconds

        Ok(Self {
            runtime,
            ports,
            ping_interval,
            ping_timeout,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            max_wait_time: max_wait,
        })
    }
}

type ResultReceiver = tokio::sync::mpsc::Receiver<(IpAddr, Option<String>, u16)>;
type HandlesReceiver = crossbeam::channel::Receiver<tokio::task::JoinHandle<anyhow::Result<()>>>;
pub struct NetworkScannerStream {
    result_receiver: Arc<Mutex<ResultReceiver>>,
    task_handles: HandlesReceiver,
}

impl NetworkScannerStream {
    pub async fn recv(self: &Arc<Self>) -> Option<(IpAddr, Option<String>, u16)> {
        // the caller sometimes require Send, hence the Arc is necessary for socket_addr_receiver
        self.result_receiver.lock().await.recv().await
    }

    pub fn stop(self: Arc<Self>) {
        while let Ok(handle) = self.task_handles.try_recv() {
            handle.abort();
        }
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub is_open: bool,
}

pub struct NetworkScanEntry {
    pub ip: IpAddr,
    pub port: u16,
}

impl TryFrom<NetworkScannerParams> for NetworkScanner {
    type Error = anyhow::Error;

    fn try_from(value: NetworkScannerParams) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanMethod {
    Ping,
    Broadcast,
    Zeroconf,
}

impl TryFrom<&str> for ScanMethod {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ping" | "Ping" => Ok(ScanMethod::Ping),
            "broadcast" | "Broadcast" => Ok(ScanMethod::Broadcast),
            "zeroconf" | "ZeroConf" => Ok(ScanMethod::Zeroconf),
            _ => Err(anyhow::anyhow!("Invalid scan method")),
        }
    }
}

impl Display for ScanMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScanMethod::Ping => "ping",
            ScanMethod::Broadcast => "broadcast",
            ScanMethod::Zeroconf => "zeroconf",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, derive_builder::Builder, Serialize, Deserialize, Default)]
pub struct NetworkScannerParams {
    pub ports: Vec<u16>,
    pub ping_interval: Option<u64>,     // in milliseconds
    pub ping_timeout: Option<u64>,      // in milliseconds
    pub broadcast_timeout: Option<u64>, // in milliseconds
    pub port_scan_timeout: Option<u64>, // in milliseconds
    pub netbios_timeout: Option<u64>,   // in milliseconds
    pub max_wait_time: Option<u64>,     // max_wait for entire scan duration in milliseconds, suggested!
}
