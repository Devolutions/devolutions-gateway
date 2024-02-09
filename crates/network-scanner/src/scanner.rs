use crate::{
    ip_utils::IpAddrRange,
    netbios::netbios_query_scan,
    ping::ping_range,
    port_discovery::{scan_ports, PortScanResult},
    task_utils::TaskManager,
};

use anyhow::Context;
use std::{fmt::Display, net::IpAddr, sync::Arc, time::Duration};

use tokio::sync::Mutex;

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

        task_executor.run(move |context, task_manager| async move {
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
                    tracing::debug!("IP: {:?} already in cache", ip);
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

                let (runtime, ports, port_sender, ip_cache) =
                    (runtime.clone(), ports.clone(), port_sender.clone(), ip_cache.clone());

                task_manager.spawn(move |task_manager| async move {
                    tracing::info!("Scanning ports for: {:?}", ip);

                    let mut port_scan_receiver =
                        scan_ports(ip, &ports, runtime, port_scan_timeout, task_manager).await?;

                    while let Some(res) = port_scan_receiver.recv().await {
                        tracing::trace!("Port scan result: {:?}", res);
                        if let PortScanResult::Open(socket_addr) = res {
                            let dns = ip_cache.get(&ip).as_deref().cloned().flatten();
                            port_sender.send((ip, dns, socket_addr.port())).await?;
                        }
                    }
                    tracing::info!("Port scan finished for: {:?}", ip);
                    anyhow::Ok(())
                });
            }

            anyhow::Ok(())
        });

        task_executor.run(move |context, task_manager| async move {
            let TaskExecutionContext {
                subnets,
                broadcast_timeout,
                runtime,
                ip_sender,
                ..
            } = context;

            for subnet in subnets {
                let (runtime, ip_sender) = (runtime.clone(), ip_sender.clone());
                task_manager.spawn(move |task_manager: crate::task_utils::TaskManager| async move {
                    let mut receiver = broadcast(subnet.broadcast, broadcast_timeout, runtime, task_manager).await?;
                    while let Some(ip) = receiver.recv().await {
                        tracing::trace!("Broadcast received: {:?}", ip);
                        ip_sender.send((ip.into(), None)).await?;
                    }
                    anyhow::Ok(())
                });
            }
            anyhow::Ok(())
        });

        task_executor.run(move |context, task_manager| async move {
            let TaskExecutionContext {
                subnets,
                netbios_timeout,
                runtime,
                ip_sender,
                ..
            } = context;

            let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();

            for ip_range in ip_ranges {
                let (runtime, ip_sender, task_manager) = (runtime.clone(), ip_sender.clone(), task_manager.clone());
                let mut receiver = netbios_query_scan(
                    runtime,
                    ip_range,
                    netbios_timeout,
                    Duration::from_millis(20),
                    task_manager,
                )?;
                while let Some(res) = receiver.recv().await {
                    ip_sender.send(res).await?;
                }
            }
            anyhow::Ok(())
        });

        task_executor.run(move |context, task_manager| async move {
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
                let (task_manager, runtime, ip_sender) = (task_manager.clone(), runtime.clone(), ip_sender.clone());
                let should_ping = should_ping.clone();
                let mut receiver = ping_range(
                    runtime,
                    ip_range,
                    ping_interval,
                    ping_timeout,
                    should_ping,
                    task_manager,
                )?;

                while let Some(ip) = receiver.recv().await {
                    tracing::trace!("Ping received: {:?}", ip);
                    ip_sender.send((ip, None)).await?;
                }
            }
            anyhow::Ok(())
        });

        let TaskExecutionRunner {
            context: TaskExecutionContext { port_receiver, .. },
            task_manager,
        } = task_executor;

        task_manager.stop_timeout(self.max_wait_time);

        Ok({
            Arc::new(NetworkScannerStream {
                result_receiver: port_receiver,
                task_manager,
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
pub struct NetworkScannerStream {
    result_receiver: Arc<Mutex<ResultReceiver>>,
    task_manager: TaskManager,
}

impl NetworkScannerStream {
    pub async fn recv(self: &Arc<Self>) -> Option<(IpAddr, Option<String>, u16)> {
        // the caller sometimes require Send, hence the Arc is necessary for socket_addr_receiver
        self.result_receiver.lock().await.recv().await
    }
    pub async fn recv_timeout(
        self: &Arc<Self>,
        duration: Duration,
    ) -> anyhow::Result<Option<(IpAddr, Option<String>, u16)>> {
        tokio::time::timeout(duration, self.result_receiver.lock().await.recv())
            .await
            .context("recv_timeout timed out")
    }

    pub fn stop(self: Arc<Self>) {
        self.task_manager.stop();
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, derive_builder::Builder, Default)]
pub struct NetworkScannerParams {
    pub ports: Vec<u16>,
    pub ping_interval: Option<u64>,     // in milliseconds
    pub ping_timeout: Option<u64>,      // in milliseconds
    pub broadcast_timeout: Option<u64>, // in milliseconds
    pub port_scan_timeout: Option<u64>, // in milliseconds
    pub netbios_timeout: Option<u64>,   // in milliseconds
    pub max_wait_time: Option<u64>,     // max_wait for entire scan duration in milliseconds, suggested!
}
