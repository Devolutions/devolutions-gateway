use crate::broadcast::asynchronous::broadcast;
use crate::ip_utils::IpAddrRange;
use crate::mdns::{self, MdnsDaemon};
use crate::netbios::{netbios_query_scan, NetBiosResult};
use crate::ping::{ping_range, PingEvent};
use crate::port_discovery::{scan_ports, PortScanResult};
use crate::task_utils::{ScanEntryReceiver, TaskExecutionContext, TaskExecutionRunner, TaskManager};
use anyhow::Context;
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use typed_builder::TypedBuilder;

/// Represents a network scanner for discovering devices and their services over a network.
#[derive(Clone)]
pub struct NetworkScanner {
    /// A list of ports to scan on discovered devices.
    pub ports: Vec<u16>,
    /// The runtime environment for socket operations, wrapped in an `Arc` for thread-safe sharing.
    pub(crate) runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    /// A daemon for Multicast DNS (mDNS) operations, handling service discovery.
    pub(crate) mdns_daemon: MdnsDaemon,
    /// The interval between ping operations.
    pub ping_interval: Duration,
    /// The maximum amount of time to wait for a ping response.
    pub ping_timeout: Duration,
    /// The maximum amount of time to wait for responses to a broadcast request.
    pub broadcast_timeout: Duration,
    /// The maximum amount of time to wait for a tcp port scan response.
    pub port_scan_timeout: Duration,
    /// The maximum amount of time to wait for a NetBIOS query response.
    pub netbios_timeout: Duration,
    /// The interval between successive NetBIOS query attempts.
    pub netbios_interval: Duration,
    /// The maximum amount of time to wait for individual mDNS query response.
    pub mdns_query_timeout: Duration,
    /// The overall maximum duration to wait for the entire scanning process to complete.
    pub max_wait_time: Duration,
}

impl NetworkScanner {
    pub fn start(&self) -> anyhow::Result<Arc<NetworkScannerStream>> {
        let mut task_executor = TaskExecutionRunner::new(self.clone())?;

        task_executor.run(
            move |TaskExecutionContext {
                      ip_cache,
                      ip_receiver,
                      ports,
                      runtime,
                      port_scan_timeout,
                      port_sender,
                      ..
                  }: TaskExecutionContext,
                  task_manager| async move {
                let ip_cache = Arc::clone(&ip_cache);
                while let Some((ip, host)) = ip_receiver.lock().await.recv().await {
                    if ip_cache.read().get(&ip).is_some() {
                        if host.is_some() {
                            ip_cache.write().insert(ip, host);
                        }
                        continue;
                    }

                    ip_cache.write().insert(ip, host);

                    let (runtime, ports, port_sender, ip_cache) = (
                        Arc::clone(&runtime),
                        ports.clone(),
                        port_sender.clone(),
                        Arc::clone(&ip_cache),
                    );

                    task_manager.spawn(move |task_manager| async move {
                        debug!(scanning_ip = ?ip);

                        let dns_look_up_res = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());

                        let mut port_scan_receiver =
                            scan_ports(ip, &ports, runtime, port_scan_timeout, task_manager).await?;

                        let dns = dns_look_up_res.await?;

                        ip_cache.write().insert(ip, dns.clone());

                        while let Some(res) = port_scan_receiver.recv().await {
                            trace!(port_scan_result = ?res);
                            if let PortScanResult::Open(socket_addr) = res {
                                let dns = ip_cache.read().get(&ip).cloned().flatten();

                                port_sender
                                    .send(ScanEntry::Regular {
                                        addr: ip,
                                        hostname: dns,
                                        port: socket_addr.port(),
                                        service_type: None,
                                    })
                                    .await?;
                            }
                        }
                        anyhow::Ok(())
                    });
                }

                anyhow::Ok(())
            },
        );

        task_executor.run(
            move |TaskExecutionContext {
                      runtime,
                      ip_sender,
                      subnets,
                      broadcast_timeout,
                      ..
                  }: TaskExecutionContext,
                  task_manager| async move {
                for subnet in subnets {
                    debug!(broadcasting_to_subnet = ?subnet);
                    let (runtime, ip_sender) = (Arc::clone(&runtime), ip_sender.clone());

                    task_manager.spawn(move |task_manager: TaskManager| async move {
                        let mut receiver =
                            broadcast(subnet.broadcast, broadcast_timeout, runtime, task_manager).await?;

                        while let Some(ip) = receiver.recv().await {
                            trace!(broadcast_sent_ip = ?ip);
                            ip_sender.send((ip.into(), None)).await?;
                        }
                        anyhow::Ok(())
                    });
                }
                anyhow::Ok(())
            },
        );

        task_executor.run(
            move |TaskExecutionContext {
                      subnets,
                      netbios_timeout,
                      netbios_interval,
                      runtime,
                      ip_sender,
                      ..
                  }: TaskExecutionContext,
                  task_manager| async move {
                let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();
                debug!(netbios_query_ip_ranges = ?ip_ranges);

                for ip_range in ip_ranges {
                    let IpAddrRange::V4(ip_range) = ip_range else {
                        continue;
                    };
                    let (runtime, ip_sender, task_manager) =
                        (Arc::clone(&runtime), ip_sender.clone(), task_manager.clone());

                    let mut receiver =
                        netbios_query_scan(runtime, ip_range, netbios_timeout, netbios_interval, task_manager)?;
                    while let Some(res) = receiver.recv().await {
                        todo!()
                        // ip_sender.send(res).await?;
                    }
                }
                anyhow::Ok(())
            },
        );

        task_executor.run(
            move |TaskExecutionContext {
                      ping_interval,
                      ping_timeout,
                      runtime,
                      ip_sender,
                      subnets,
                      ip_cache,
                      ..
                  }: TaskExecutionContext,
                  task_manager| async move {
                let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();
                debug!(ping_ip_ranges = ?ip_ranges);

                let should_ping = move |ip: IpAddr| -> bool { !ip_cache.read().contains_key(&ip) };

                for ip_range in ip_ranges {
                    let (task_manager, runtime, ip_sender) =
                        (task_manager.clone(), Arc::clone(&runtime), ip_sender.clone());

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
                        debug!(ping_sent_ip = ?ip);
                        todo!()
                        // ip_sender.send(ScanEntry::Ping(ip)).await?;
                    }
                }
                anyhow::Ok(())
            },
        );

        task_executor.run(
            move |TaskExecutionContext {
                      mdns_daemon,
                      port_sender,
                      ip_cache,
                      ports,
                      mdns_query_timeout,
                      ..
                  },
                  task_manager| async move {
                let mut receiver = mdns::mdns_query_scan(mdns_daemon, task_manager, mdns_query_timeout)?;

                todo!();
                // while let Some(mut entry) = receiver.recv().await {
                //     if ip_cache.read().get(&entry.addr).is_none() {
                //         ip_cache.write().insert(entry.addr, entry.hostname.clone());
                //     }

                //     let dns_name = ip_cache.read().get(&entry.addr).cloned().flatten();
                //     entry.hostname = dns_name;

                //     if ports.contains(&entry.port) || entry.service_type.is_some() {
                //         port_sender.send(entry).await?;
                //     }
                // }

                anyhow::Ok(())
            },
        );

        let TaskExecutionRunner {
            context:
                TaskExecutionContext {
                    port_receiver,
                    mdns_daemon,
                    ..
                },
            task_manager,
        } = task_executor;

        let scanner_stream = Arc::new(NetworkScannerStream {
            result_receiver: port_receiver,
            task_manager,
            mdns_daemon,
        });

        let scanner_stream_clone = Arc::clone(&scanner_stream);
        let max_wait_time = self.max_wait_time;

        tokio::spawn(async move {
            tokio::time::sleep(max_wait_time).await;
            scanner_stream_clone.stop();
        });

        Ok(scanner_stream)
    }

    pub fn new(
        NetworkScannerParams {
            ports,
            ping_timeout,
            max_wait_time: max_wait,
            ping_interval,
            broadcast_timeout,
            port_scan_timeout,
            netbios_timeout,
            netbios_interval,
            mdns_query_timeout,
        }: NetworkScannerParams,
    ) -> anyhow::Result<Self> {
        let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

        let ping_timeout = Duration::from_millis(ping_timeout);
        let ping_interval = Duration::from_millis(ping_interval);
        let broadcast_timeout = Duration::from_millis(broadcast_timeout);
        let port_scan_timeout = Duration::from_millis(port_scan_timeout);
        let netbios_timeout = Duration::from_millis(netbios_timeout);
        let netbios_interval = Duration::from_millis(netbios_interval);
        let mdns_query_timeout = Duration::from_millis(mdns_query_timeout);
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
            mdns_query_timeout,
            max_wait_time: max_wait,
            mdns_daemon: MdnsDaemon::new()?,
        })
    }
}

#[derive(Debug)]
pub enum ScanEntry {
    Ping(PingEvent),
    Netbios(NetBiosResult),
    Regular {
        // IP address of the device
        addr: IpAddr,
        // Hostname of the device
        hostname: Option<String>,
        // Port number
        port: u16,
        // The protocol / service type listening on the port
        service_type: Option<ServiceType>,
    },
}

pub struct NetworkScannerStream {
    result_receiver: Arc<Mutex<ScanEntryReceiver>>,
    task_manager: TaskManager,
    mdns_daemon: MdnsDaemon,
}

impl NetworkScannerStream {
    pub async fn recv(self: &Arc<Self>) -> Option<ScanEntry> {
        // The caller sometimes require Send, hence the Arc is necessary for socket_addr_receiver.
        self.result_receiver.lock().await.recv().await
    }

    pub async fn recv_timeout(self: &Arc<Self>, duration: Duration) -> anyhow::Result<Option<ScanEntry>> {
        tokio::time::timeout(duration, self.result_receiver.lock().await.recv())
            .await
            .context("recv_timeout timed out")
    }

    pub fn stop(self: Arc<Self>) {
        self.task_manager.stop();
        self.mdns_daemon.stop();
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

/// The parameters for configuring a network scanner. All fields are in milliseconds.
#[derive(Debug, Clone, TypedBuilder, Default)]
pub struct NetworkScannerParams {
    pub ports: Vec<u16>,
    pub ping_interval: u64,
    pub ping_timeout: u64,
    pub broadcast_timeout: u64,
    pub port_scan_timeout: u64,
    pub netbios_timeout: u64,
    pub netbios_interval: u64,
    pub mdns_query_timeout: u64,
    pub max_wait_time: u64, // max_wait for entire scan duration in milliseconds, suggested!
}

#[derive(Debug, Clone, Copy)]
pub enum ServiceType {
    /// Remote Desktop Protocol
    Rdp,
    /// Apple Remote Desktop
    Ard,
    /// Virtual Network Computing
    Vnc,
    /// Secure Shell
    Ssh,
    /// SSH File Transfer Protocol
    Sftp,
    /// Secure Copy Protocol
    Scp,
    /// Telnet
    Telnet,
    /// Hypertext Transfer Protocol
    Http,
    /// Hypertext Transfer Protocol Secure
    Https,
    /// LDAP Protocol
    Ldap,
    /// Secure LDAP Protocol
    Ldaps,
}
