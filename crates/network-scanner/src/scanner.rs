use crate::{
    ip_utils::IpAddrRange,
    mdns::{self, MdnsDeamon},
    netbios::netbios_query_scan,
    ping::ping_range,
    port_discovery::{scan_ports, PortScanResult},
    task_utils::TaskManager,
};

use anyhow::Context;
use std::{fmt::Display, net::IpAddr, sync::Arc, time::Duration};
use typed_builder::TypedBuilder;

use tokio::sync::Mutex;

use crate::{
    broadcast::asynchronous::broadcast,
    task_utils::{TaskExecutionContext, TaskExecutionRunner},
};

#[derive(Clone)]
pub struct NetworkScanner {
    pub ports: Vec<u16>,

    pub(crate) runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    pub(crate) mdns_deamon: MdnsDeamon,
    pub ping_interval: Duration,     // in milliseconds
    pub ping_timeout: Duration,      // in milliseconds
    pub broadcast_timeout: Duration, // in milliseconds
    pub port_scan_timeout: Duration, // in milliseconds
    pub netbios_timeout: Duration,   // in milliseconds
    pub netbios_interval: Duration,  // in milliseconds
    /// the duration to wait for the entire scan to finish
    pub mdns_meta_query_timeout: Duration,
    /// the duration to wait for each mdns query
    pub mdns_single_query_timeout: Duration,
    /// the duration to wait for the entire scan to finish
    pub max_wait_time: Duration,
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
                if ip_cache.read().get(&ip).is_some() {
                    if host.is_some() {
                        ip_cache.write().insert(ip, host);
                    }
                    continue;
                }

                ip_cache.write().insert(ip, host);

                let (runtime, ports, port_sender, ip_cache) =
                    (runtime.clone(), ports.clone(), port_sender.clone(), ip_cache.clone());

                task_manager.spawn(move |task_manager| async move {
                    tracing::debug!(scanning_ip = ?ip);

                    let dns_look_up_res = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());

                    let mut port_scan_receiver =
                        scan_ports(ip, &ports, runtime, port_scan_timeout, task_manager).await?;

                    let dns = dns_look_up_res.await?;

                    ip_cache.write().insert(ip, dns.clone());

                    while let Some(res) = port_scan_receiver.recv().await {
                        tracing::trace!(port_scan_result = ?res);
                        if let PortScanResult::Open(socket_addr) = res {
                            let dns = ip_cache.read().get(&ip).cloned().flatten();
                            port_sender.send((ip, dns, socket_addr.port(), None)).await?;
                        }
                    }
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
                        tracing::trace!(broadcast_sent_ip = ?ip);
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
                netbios_interval,
                runtime,
                ip_sender,
                ..
            } = context;

            let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();

            for ip_range in ip_ranges {
                let (runtime, ip_sender, task_manager) = (runtime.clone(), ip_sender.clone(), task_manager.clone());
                let mut receiver =
                    netbios_query_scan(runtime, ip_range, netbios_timeout, netbios_interval, task_manager)?;
                while let Some(res) = receiver.recv().await {
                    tracing::debug!(netbios_query_sent_ip = ?res.0);
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

            let should_ping = move |ip: IpAddr| -> bool { !ip_cache.read().contains_key(&ip) };

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
                    tracing::debug!(ping_sent_ip = ?ip);
                    ip_sender.send((ip, None)).await?;
                }
            }
            anyhow::Ok(())
        });

        task_executor.run(
            move |TaskExecutionContext {
                      mdns_deamon,
                      port_sender,
                      ip_cache,
                      ports,
                      ..
                  },
                  task_manager| async move {
                let mut receiver = mdns::mdns_query_scan(
                    mdns_deamon,
                    task_manager,
                    Duration::from_secs(10),
                    Duration::from_secs(3),
                )?;

                while let Some((ip, server, port, protocol)) = receiver.recv().await {
                    if ip_cache.read().get(&ip).is_none() {
                        ip_cache.write().insert(ip, server.clone());
                    }
                    let dns_name = ip_cache.read().get(&ip).cloned().flatten();
                    if ports.contains(&port) || protocol.is_some() {
                        port_sender.send((ip, dns_name, port, protocol)).await?;
                    }
                }

                anyhow::Ok(())
            },
        );

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
            netbios_interval,
            mdns_meta_query_timeout,
            mdns_single_query_timeout,
        } = params;

        let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

        let ping_timeout = Duration::from_millis(ping_timeout);
        let ping_interval = Duration::from_millis(ping_interval);
        let broadcast_timeout = Duration::from_millis(broadcast_timeout);
        let port_scan_timeout = Duration::from_millis(port_scan_timeout);
        let netbios_timeout = Duration::from_millis(netbios_timeout);
        let netbios_interval = Duration::from_millis(netbios_interval);
        let mdns_meta_query_timeout = Duration::from_millis(mdns_meta_query_timeout);
        let mdns_single_query_timeout = Duration::from_millis(mdns_single_query_timeout);
        let max_wait = Duration::from_millis(max_wait);

        Ok(Self {
            runtime,
            ports,
            ping_interval,
            ping_timeout,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            netbios_interval,
            mdns_meta_query_timeout,
            mdns_single_query_timeout,
            max_wait_time: max_wait,
            mdns_deamon: MdnsDeamon::new()?,
        })
    }
}

pub type ScanEntry = (IpAddr, Option<String>, u16, Option<Protocol>);
type ResultReceiver = tokio::sync::mpsc::Receiver<ScanEntry>;
pub struct NetworkScannerStream {
    result_receiver: Arc<Mutex<ResultReceiver>>,
    task_manager: TaskManager,
}

impl NetworkScannerStream {
    pub async fn recv(self: &Arc<Self>) -> Option<ScanEntry> {
        // the caller sometimes require Send, hence the Arc is necessary for socket_addr_receiver
        self.result_receiver.lock().await.recv().await
    }
    pub async fn recv_timeout(self: &Arc<Self>, duration: Duration) -> anyhow::Result<Option<ScanEntry>> {
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

#[derive(Debug, Clone, TypedBuilder, Default)]
pub struct NetworkScannerParams {
    pub ports: Vec<u16>,
    pub ping_interval: u64,             // in milliseconds
    pub ping_timeout: u64,              // in milliseconds
    pub broadcast_timeout: u64,         // in milliseconds
    pub port_scan_timeout: u64,         // in milliseconds
    pub netbios_timeout: u64,           // in milliseconds
    pub netbios_interval: u64,          // in milliseconds
    pub mdns_meta_query_timeout: u64,   // in milliseconds
    pub mdns_single_query_timeout: u64, // in milliseconds
    pub max_wait_time: u64,             // max_wait for entire scan duration in milliseconds, suggested!
}

#[derive(Debug, Clone)]
pub enum Protocol {
    /// Wayk Remote Desktop Protocol
    Wayk,
    /// Remote Desktop Protocol
    Rdp,
    /// Apple Remote Desktop
    Ard,
    /// Virtual Network Computing
    Vnc,
    /// Secure Shell
    Ssh,
    /// PowerShell over SSH transport
    SshPwsh,
    /// SSH File Transfer Protocol
    Sftp,
    /// Secure Copy Protocol
    Scp,
    /// Telnet
    Telnet,
    /// PowerShell over WinRM via HTTP transport
    WinrmHttpPwsh,
    /// PowerShell over WinRM via HTTPS transport
    WinrmHttpsPwsh,
    /// Hypertext Transfer Protocol
    Http,
    /// Hypertext Transfer Protocol Secure
    Https,
    /// LDAP Protocol
    Ldap,
    /// Secure LDAP Protocol
    Ldaps,
    /// Devolutions Gateway Tunnel (generic JMUX tunnel)
    Tunnel,
}
