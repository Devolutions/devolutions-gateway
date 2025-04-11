use crate::broadcast::asynchronous::broadcast;
use crate::ip_utils::IpAddrRange;
use crate::mdns::{self, MdnsDaemon, MdnsResult};
use crate::netbios::netbios_query_scan;
use crate::ping::{ping_range, PingFailedReason};
use crate::port_discovery::{scan_ports, PortScanResult};
use crate::task_utils::{TaskExecutionContext, TaskExecutionRunner, TaskManager};
use anyhow::Context;
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use typed_builder::TypedBuilder;

/// Represents a network scanner for discovering devices and their services over a network.
#[derive(Clone)]
pub struct NetworkScanner {
    /// The runtime environment for socket operations, wrapped in an `Arc` for thread-safe sharing.
    pub(crate) runtime: Arc<network_scanner_net::runtime::Socket2Runtime>,
    /// A daemon for Multicast DNS (mDNS) operations, handling service discovery.
    pub(crate) mdns_daemon: Option<MdnsDaemon>,

    /// Configuration settings for the network scanner
    pub(crate) config: ScannerConfig,
    /// Toggles for enabling or disabling specific features of the scanner.
    pub(crate) toggle: ScannerToggles,
}

impl NetworkScanner {
    pub fn start(&self) -> anyhow::Result<NetworkScannerStream> {
        let (mut task_executor, result_receiver) = TaskExecutionRunner::new(self.clone())?;

        start_port_scan(&mut task_executor);
        start_dns_look_up(&mut task_executor);

        if self.toggle.enable_broadcast {
            start_broadcast(&mut task_executor);
        }

        start_netbios(&mut task_executor);

        start_ping(&mut task_executor);

        if self.toggle.enable_zeroconf {
            start_mdns(&mut task_executor);
        }

        let TaskExecutionRunner {
            context: TaskExecutionContext { mdns_daemon, .. },
            task_manager,
        } = task_executor;

        let task_manager_clone = task_manager.clone();
        let mdns_daemon_clone = mdns_daemon.clone();

        let scanner_stream = NetworkScannerStream {
            result_receiver,
            task_manager,
            mdns_daemon,
        };

        let max_wait_time = self.config.max_wait_time;

        tokio::spawn(async move {
            tokio::time::sleep(max_wait_time).await;
            task_manager_clone.stop();
            if let Some(daemon) = &mdns_daemon_clone {
                daemon.stop();
            }
        });

        return Ok(scanner_stream);

        fn start_dns_look_up(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          ip_cache,
                          ip_sender,
                          result_sender,
                          toggles,
                          ..
                      }: TaskExecutionContext,
                      task_executor| async move {
                    let enable_dns_resolve = toggles.enable_resolve_dns;
                    let mut ip_receiver = ip_sender.subscribe();

                    while let Ok((ip, host)) = ip_receiver.recv().await {
                        let ip_cache = Arc::clone(&ip_cache);
                        let result_sender = result_sender.clone();
                        let existing_dns = {
                            let binding = ip_cache.read();
                            binding.get(&ip).cloned()
                        };
                        // Write first, to aviod new incoming same IP address,
                        // The host will be updated later to the correct one anyway
                        // Put in it's now scope to avoid holding the lock for too long
                        {
                            ip_cache.write().insert(ip, host.clone());
                        }

                        // Spawn a new task for each IP address
                        task_executor.spawn_no_sub_task(async move {
                            trace!(ip = ?ip, host = ?host, "DNS lookup");
                            let (update_dns, ip, dns) = match existing_dns {
                                Some(None) if host.is_some() => {
                                    // If the IP address is in the cache but DNS resolution was not successful before and we have a new host coming in, update
                                    (true, ip, host)
                                }
                                None if enable_dns_resolve => {
                                    // If the IP address is not in the cache, resolve the DNS
                                    let resolve_dns = tokio::task::spawn_blocking(move || {
                                        dns_lookup::lookup_addr(&ip).context("Failed to resolve DNS").ok()
                                    })
                                    .await
                                    .context("Failed to spawn blocking task")?;

                                    let one_or_the_other = resolve_dns.or(host);
                                    (true, ip, one_or_the_other)
                                }
                                None => {
                                    // If the IP address is not in the cache, just update
                                    (true, ip, host)
                                }
                                _ => {
                                    // If the IP address is already in the cache, do nothing
                                    // Already exists DNS/ or DNS not exists but new host is None as well
                                    (false, ip, host)
                                }
                            };

                            if update_dns {
                                if let Some(dns) = &dns {
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::Dns {
                                            ip_addr: ip,
                                            hostname: dns.to_owned(),
                                        }))
                                        .await?;
                                }
                                ip_cache.write().insert(ip, dns);
                            }

                            anyhow::Ok(())
                        });
                    }

                    anyhow::Ok(())
                },
            );
        }

        fn start_port_scan(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          ip_cache,
                          runtime,
                          result_sender,
                          ip_sender,
                          configs,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let ip_cache = Arc::clone(&ip_cache);

                    let ports = configs.ports.clone();
                    let mut ip_receiver = ip_sender.subscribe();

                    while let Ok((ip, _)) = ip_receiver.recv().await {
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
                        trace!(broadcasting_to_subnet = ?subnet);
                        let (runtime, ip_sender) = (Arc::clone(&runtime), ip_sender.clone());
                        task_manager.spawn(move |task_manager: TaskManager| async move {
                            let mut receiver =
                                broadcast(subnet.broadcast, broadcast_timeout, runtime, task_manager).await?;

                            while let Some(ip) = receiver.recv().await {
                                trace!(broadcast_sent_ip = ?ip);
                                ip_sender.send((ip.into(), None))?;
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

                    let subnet_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();
                    debug!(netbios_query_ip_ranges = ?subnet_ranges);

                    for subnet_range in subnet_ranges {
                        let (runtime, ip_sender, task_manager) =
                            (Arc::clone(&runtime), ip_sender.clone(), task_manager.clone());

                        let IpAddrRange::V4(ip_range) = subnet_range else {
                            continue;
                        };

                        let mut receiver =
                            netbios_query_scan(runtime, ip_range, netbios_timeout, netbios_interval, task_manager)?;

                        while let Some(res) = receiver.recv().await {
                            trace!(netbios_query_sent_ip = ?res.0);
                            ip_sender.send(res)?;
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
                    let enable_ping_start = toggles.enable_ping_start;

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
                            trace!(ping_sent_ip = ?ping_event);

                            match ping_event {
                                crate::ping::PingEvent::Success { ip_addr, time } => {
                                    ip_sender.send((ip_addr, None))?;
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::PingSuccess { ip_addr, time }))
                                        .await?;
                                }
                                crate::ping::PingEvent::Start { ip_addr } if enable_ping_start => {
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::PingStart { ip_addr }))
                                        .await?;
                                }
                                crate::ping::PingEvent::Failed { ip_addr, reason } => {
                                    result_sender
                                        .send(ScanEntry::ScanEvent(ScanEvent::PingFailed { ip_addr, reason }))
                                        .await?;
                                }
                                _ => {}
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
                          configs,
                          ip_sender,
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

                    while let Some(MdnsResult {
                        addr,
                        hostname,
                        port,
                        service_type,
                    }) = receiver.recv().await
                    {
                        // Let the DNS resolver to figure it out
                        // We can send the result directly from here, but there's no harm to let port scanner to check wanted ports for that machine anyway
                        ip_sender.send((addr, hostname.clone()))?;

                        if ports.contains(&port) || service_type.is_some() {
                            result_sender
                                .send(ScanEntry::Result {
                                    addr,
                                    hostname,
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

    pub fn new(NetworkScannerParams { config, toggle }: NetworkScannerParams) -> anyhow::Result<Self> {
        let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;

        let mdns_daemon = if toggle.enable_zeroconf {
            Some(MdnsDaemon::new()?)
        } else {
            None
        };

        debug!(?config, ?toggle, "Starting network scanner");

        Ok(Self {
            config,
            toggle,
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
    result_receiver: mpsc::Receiver<ScanEntry>,
    task_manager: TaskManager,
    mdns_daemon: Option<MdnsDaemon>,
}

impl NetworkScannerStream {
    pub async fn recv(self: &mut Self) -> Option<ScanEntry> {
        // The caller sometimes require Send, hence the Arc is necessary for socket_addr_receiver.
        self.result_receiver.recv().await
    }

    pub async fn recv_timeout(self: &mut Self, duration: Duration) -> anyhow::Result<Option<ScanEntry>> {
        tokio::time::timeout(duration, self.result_receiver.recv())
            .await
            .context("recv_timeout timed out")
    }

    pub fn stop(self: &Self) {
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
    pub enable_ping_start: bool,
    pub enable_broadcast: bool,
    pub enable_subnet_scan: bool,
    pub enable_zeroconf: bool,
    pub enable_resolve_dns: bool,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub ports: Vec<u16>,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub broadcast_timeout: Duration,
    pub port_scan_timeout: Duration,
    pub netbios_timeout: Duration,
    pub netbios_interval: Duration,
    pub mdns_query_timeout: Duration,
    pub max_wait_time: Duration,
    pub ip_ranges: Vec<IpAddrRange>,
}

/// The parameters for configuring a network scanner. All fields are in milliseconds.
#[derive(Debug, Clone, TypedBuilder)]
pub struct NetworkScannerParams {
    pub config: ScannerConfig,
    pub toggle: ScannerToggles,
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
