use crate::broadcast::asynchronous::broadcast;
use crate::ip_utils::IpAddrRange;
use crate::mdns::{self, MdnsDaemon};
use crate::netbios::netbios_query_scan;
use crate::ping::{ping_range, PingFailedReason};
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
    /// The runtime environment for socket operations, wrapped in an `Arc` for thread-safe sharing.
    pub(crate) runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    /// A daemon for Multicast DNS (mDNS) operations, handling service discovery.
    pub(crate) mdns_daemon: Option<MdnsDaemon>,

    /// Configuration settings for the network scanner
    pub(crate) configs: ScannerConfig,
    /// Toggles for enabling or disabling specific features of the scanner.
    pub(crate) toggles: ScannerToggles,
}

impl NetworkScanner {
    pub fn start(&self) -> anyhow::Result<Arc<NetworkScannerStream>> {
        let mut task_executor = TaskExecutionRunner::new(self.clone())?;

        start_port_scan(&mut task_executor);

        if !self.toggles.disable_broadcast {
            start_broadcast(&mut task_executor);
        }

        start_netbios(&mut task_executor);

        start_ping(&mut task_executor);

        if !self.toggles.disable_zeroconf {
            start_mdns(&mut task_executor);
        }

        let TaskExecutionRunner {
            context:
                TaskExecutionContext {
                    result_receiver: port_receiver,
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
        let max_wait_time = Duration::from_millis(self.configs.max_wait_time);

        tokio::spawn(async move {
            tokio::time::sleep(max_wait_time).await;
            scanner_stream_clone.stop();
        });

        return Ok(scanner_stream);

        fn start_port_scan(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          ip_cache,
                          ip_receiver,
                          runtime,
                          result_sender,
                          configs,
                          toggles,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let ip_cache = Arc::clone(&ip_cache);

                    let ports = configs.ports.clone();
                    let disable_dns_resolve = toggles.disable_resolve_dns;

                    while let Some((ip, host)) = ip_receiver.lock().await.recv().await {
                        // ==========================Check cache and dns resolve ==============================
                        // The host is optional, it can be sent from a netbios query or a mDNS query that have hostname
                        // Or if can be None if it's from a ping or broadcast scan

                        // Check if the IP is already in the cache (if there is, that means we had it scanned before)
                        let is_new = ip_cache.read().get(&ip).is_none();
                        let updated_dns = if is_new {
                            let resolve_dns = if !disable_dns_resolve {
                                tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip))
                                    .await?
                                    .ok()
                            } else {
                                None
                            };
                            let final_dns = resolve_dns.or(host);
                            ip_cache.write().insert(ip, final_dns.clone());
                            final_dns
                        } else if host.is_some() {
                            // If the host is not None, we should update the cache with the new hostname
                            ip_cache.write().insert(ip, host.clone());
                            host
                        } else {
                            None
                        };

                        if let Some(dns) = updated_dns {
                            result_sender
                                .send(ScanEntry::ScanEvent(ScanEvent::Dns {
                                    ip_addr: ip,
                                    hostname: dns,
                                }))
                                .await?;
                        }

                        if !is_new {
                            continue;
                        }

                        // ======================end of check cache and dns resolve =========================

                        let (runtime, ports, result_sender, ip_cache, port_scan_timeout) = (
                            Arc::clone(&runtime),
                            ports.clone(),
                            result_sender.clone(),
                            Arc::clone(&ip_cache),
                            configs.port_scan_timeout,
                        );

                        task_manager.spawn(move |task_manager| async move {
                            debug!(scanning_ip = ?ip);

                            let mut port_scan_receiver =
                                scan_ports(ip, &ports, runtime, port_scan_timeout, task_manager).await?;

                            while let Some(res) = port_scan_receiver.recv().await {
                                trace!(port_scan_result = ?res);
                                if let PortScanResult::Open(socket_addr) = res {
                                    let dns = ip_cache.read().get(&ip).cloned().flatten();

                                    result_sender
                                        .send(ScanEntry::Result {
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
        }

        fn start_broadcast(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          runtime,
                          ip_sender,
                          configs,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let broadcast_subnet = configs.broadcast_subnet;
                    let broadcast_timeout = configs.broadcast_timeout;
                    for subnet in broadcast_subnet {
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
        }

        fn start_netbios(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          runtime,
                          ip_sender,
                          configs,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let netbios_timeout = configs.netbios_timeout;
                    let netbios_interval = configs.netbios_interval;
                    let subnets = configs.broadcast_subnet;

                    let ip_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();
                    debug!(netbios_query_ip_ranges = ?ip_ranges);

                    for ip_range in ip_ranges {
                        let (runtime, ip_sender, task_manager) =
                            (Arc::clone(&runtime), ip_sender.clone(), task_manager.clone());

                        let IpAddrRange::V4(ip_range) = ip_range else {
                            continue;
                        };

                        let mut receiver =
                            netbios_query_scan(runtime, ip_range, netbios_timeout, netbios_interval, task_manager)?;

                        while let Some(res) = receiver.recv().await {
                            debug!(netbios_query_sent_ip = ?res.0);
                            ip_sender.send(res).await?;
                        }
                    }
                    anyhow::Ok(())
                },
            );
        }

        fn start_ping(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          runtime,
                          ip_sender,
                          ip_cache,
                          result_sender,
                          toggles,
                          configs,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let should_ping = move |ip: IpAddr| -> bool { !ip_cache.read().contains_key(&ip) };

                    let ping_interval = configs.ping_interval;
                    let ping_timeout = configs.ping_timeout;
                    let range_to_ping = configs.range_to_ping;
                    let disable_ping_event = toggles.disable_ping_event;

                    for ip_range in range_to_ping {
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

                        while let Some(ping_event) = receiver.recv().await {
                            debug!(ping_sent_ip = ?ping_event);
                            if let crate::ping::PingEvent::Success { ip_addr, .. } = ping_event {
                                ip_sender.send((ip_addr, None)).await?;
                            };

                            if disable_ping_event {
                                continue;
                            }

                            match ping_event {
                                crate::ping::PingEvent::Success { ip_addr, time } => {
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::PingSuccess { ip_addr, time }))
                                        .await?;
                                }
                                crate::ping::PingEvent::Start { ip_addr } => {
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::PingStart { ip_addr }))
                                        .await?;
                                }
                                crate::ping::PingEvent::Failed { ip_addr, reason } => {
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::PingFailed { ip_addr, reason }))
                                        .await?;
                                }
                            }
                        }
                    }
                    anyhow::Ok(())
                },
            );
        }

        fn start_mdns(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          mdns_daemon,
                          result_sender,
                          ip_cache,
                          configs,
                          ..
                      },
                      task_manager| async move {
                    // Since mDNS daemon is started at the point it's created, we set it to None in order to avoid resource waste
                    // Caller of the start_mdns function should guarantee that the daemon exists
                    let mdns_daemon = match mdns_daemon {
                        Some(daemon) => daemon,
                        None => anyhow::bail!("mDNS daemon is not available but mDNS is enabled"),
                    };

                    let mdns_query_timeout = configs.mdns_query_timeout;
                    let ports = configs.ports.clone();

                    let mut receiver = mdns::mdns_query_scan(mdns_daemon, task_manager, mdns_query_timeout)?;

                    while let Some(ScanEntry::Result {
                        addr,
                        hostname,
                        port,
                        service_type,
                    }) = receiver.recv().await
                    {
                        if ip_cache.read().get(&addr).is_none() {
                            ip_cache.write().insert(addr, hostname.clone());
                        }

                        let dns_name = ip_cache.read().get(&addr).cloned().flatten();

                        if ports.contains(&port) || service_type.is_some() {
                            result_sender
                                .send(ScanEntry::Result {
                                    addr,
                                    hostname: dns_name,
                                    port,
                                    service_type,
                                })
                                .await?;
                        }
                    }

                    anyhow::Ok(())
                },
            );
        }
    }

    pub fn new(NetworkScannerParams { configs, toggles }: NetworkScannerParams) -> anyhow::Result<Self> {
        let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

        let mdns_daemon = if toggles.disable_zeroconf {
            None
        } else {
            Some(MdnsDaemon::new()?)
        };

        Ok(Self {
            configs,
            toggles,
            mdns_daemon,
            runtime,
        })
    }
}

#[derive(Debug)]
pub enum ScanEvent {
    PingStart { ip_addr: IpAddr },
    PingFailed { ip_addr: IpAddr, reason: PingFailedReason },
    PingSuccess { ip_addr: IpAddr, time: u128 },
    Dns { ip_addr: IpAddr, hostname: String },
}

#[derive(Debug)]
pub enum ScanEntry {
    ScanEvent(ScanEvent),
    Result {
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
    mdns_daemon: Option<MdnsDaemon>,
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
        if let Some(daemon) = &self.mdns_daemon {
            daemon.stop();
        };
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

#[derive(Debug, Clone)]
pub struct ScannerToggles {
    pub disable_ping_event: bool,
    pub disable_broadcast: bool,
    pub disable_subnet_scan: bool,
    pub disable_zeroconf: bool,
    pub disable_resolve_dns: bool,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub ports: Vec<u16>,
    pub ping_interval: u64,
    pub ping_timeout: u64,
    pub broadcast_timeout: u64,
    pub port_scan_timeout: u64,
    pub netbios_timeout: u64,
    pub netbios_interval: u64,
    pub mdns_query_timeout: u64,
    pub max_wait_time: u64,
    pub ip_ranges: Vec<IpAddrRange>,
}

/// The parameters for configuring a network scanner. All fields are in milliseconds.
#[derive(Debug, Clone, TypedBuilder)]
pub struct NetworkScannerParams {
    pub configs: ScannerConfig,
    pub toggles: ScannerToggles,
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
