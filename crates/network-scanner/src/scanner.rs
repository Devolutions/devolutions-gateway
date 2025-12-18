use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use typed_builder::TypedBuilder;

use crate::broadcast::asynchronous::broadcast;
use crate::event_bus::{EventBus, RawIpEvent, TypedReceiver};
use crate::ip_utils::IpAddrRange;
use crate::mdns::{self, MdnsDaemon, MdnsEvent};
use crate::named_port::MaybeNamedPort;
use crate::netbios::netbios_query_scan;
use crate::ping::ping_range;
use crate::port_discovery::{TcpKnockEvent, scan_ports};
use crate::task_utils::{TaskExecutionContext, TaskExecutionRunner, TaskManager};

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
        let mut task_executor = TaskExecutionRunner::new(self.clone())?;

        start_try_get_dns_name_for_service(&mut task_executor);
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
            context: TaskExecutionContext {
                mdns_daemon, event_bus, ..
            },
            task_manager,
        } = task_executor;

        let task_manager_clone = task_manager.clone();
        let mdns_daemon_clone = mdns_daemon.clone();

        let scanner_stream = NetworkScannerStream {
            event_bus,
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

        fn start_try_get_dns_name_for_service(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          event_bus, ip_cache, ..
                      }: TaskExecutionContext,
                      _| async move {
                    let (result_sender, mut receiver) = event_bus.split::<_, TcpKnockEvent>();

                    while let Ok(event) = receiver.recv().await {
                        let ip = event.ip();
                        let host = ip_cache.read().get(&ip).cloned().flatten();
                        result_sender.send(TcpKnockWithHost { tcp_knock: event, host })?;
                    }
                    anyhow::Ok(())
                },
            );
        }

        fn start_dns_look_up(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          ip_cache,
                          event_bus,
                          toggles,
                          ..
                      }: TaskExecutionContext,
                      task_executor| async move {
                    let enable_dns_resolve = toggles.enable_resolve_dns;

                    let (event_sender, mut ip_receiver) = event_bus.split::<_, RawIpEvent>();

                    while let Ok(event) = ip_receiver.recv().await {
                        let Some(ip) = event.success() else {
                            continue;
                        };

                        let ip_cache = Arc::clone(&ip_cache);
                        if ip_cache.read().contains_key(&ip) {
                            continue;
                        }

                        // Write first, to avoid new incoming same IP address,
                        // The host will be updated later to the correct one anyway
                        // Put in it's now scope to avoid holding the lock for too long
                        {
                            ip_cache.write().insert(ip, None);
                        }

                        let event_sender = event_sender.clone();

                        // Spawn a new task for each IP address
                        task_executor.spawn_no_sub_task(async move {
                            trace!(ip = ?ip, "DNS lookup");
                            if enable_dns_resolve {
                                event_sender.send(DnsEvent::Start { ip })?;

                                // If the IP address is not in the cache, resolve the DNS
                                let resolve_dns = tokio::task::spawn_blocking(move || {
                                    dns_lookup::lookup_addr(&ip).context("Failed to resolve DNS").ok()
                                })
                                .await
                                .context("Failed to spawn blocking task")?;

                                ip_cache.write().insert(ip, resolve_dns);
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
                          runtime,
                          event_bus,
                          configs,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let ports = configs.ports.clone();

                    let (result_sender, mut receiver) = event_bus.split::<_, RawIpEvent>();

                    while let Ok(event) = receiver.recv().await {
                        let Some(ip) = event.success() else {
                            continue;
                        };

                        let (runtime, ports, result_sender, port_scan_timeout) = (
                            Arc::clone(&runtime),
                            ports.clone(),
                            result_sender.clone(),
                            configs.port_scan_timeout,
                        );

                        task_manager.spawn(move |task_manager| async move {
                            debug!(scanning_ip = ?ip);

                            let port_scan_receiver =
                                scan_ports(ip, &ports, runtime, port_scan_timeout, task_manager).await?;

                            result_sender.send_from(port_scan_receiver).await
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
                          configs,
                          event_bus,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let broadcast_subnet = configs.broadcast_subnet;
                    let broadcast_timeout = configs.broadcast_timeout;
                    let ip_sender = event_bus.sender();

                    for subnet in broadcast_subnet {
                        trace!(broadcasting_to_subnet = ?subnet);
                        let (runtime, sender) = (Arc::clone(&runtime), ip_sender.clone());
                        task_manager.spawn(move |task_manager: TaskManager| async move {
                            let mut receiver =
                                broadcast(subnet.broadcast, broadcast_timeout, runtime, task_manager).await?;

                            while let Some(event) = receiver.recv().await {
                                trace!(broadcast_event = ?event);
                                sender.send(event)?;
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
                          configs,
                          event_bus,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let netbios_timeout = configs.netbios_timeout;
                    let netbios_interval = configs.netbios_interval;
                    let subnets = configs.broadcast_subnet;

                    let subnet_ranges: Vec<IpAddrRange> = subnets.iter().map(|subnet| subnet.into()).collect();
                    let sender = event_bus.sender();
                    debug!(netbios_query_ip_ranges = ?subnet_ranges);

                    for subnet_range in subnet_ranges {
                        let (runtime, task_manager) = (Arc::clone(&runtime), task_manager.clone());

                        let IpAddrRange::V4(ip_range) = subnet_range else {
                            continue;
                        };

                        let receiver =
                            netbios_query_scan(runtime, ip_range, netbios_timeout, netbios_interval, task_manager)?;

                        sender.send_from(receiver).await?;
                    }
                    anyhow::Ok(())
                },
            );
        }

        fn start_ping(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          runtime,
                          ip_cache,
                          configs,
                          event_bus,
                          ..
                      }: TaskExecutionContext,
                      task_manager| async move {
                    let should_ping = move |ip: IpAddr| -> bool { !ip_cache.read().contains_key(&ip) };

                    let ping_interval = configs.ping_interval;
                    let ping_timeout = configs.ping_timeout;
                    let range_to_ping = configs.range_to_ping;

                    let sender = event_bus.sender();

                    for ip_range in range_to_ping {
                        let (task_manager, runtime) = (task_manager.clone(), Arc::clone(&runtime));
                        let should_ping = should_ping.clone();
                        let receiver = ping_range(
                            runtime,
                            ip_range,
                            ping_interval,
                            ping_timeout,
                            should_ping,
                            task_manager,
                        )?;

                        sender.send_from(receiver).await?;
                    }
                    anyhow::Ok(())
                },
            );
        }

        fn start_mdns(task_executor: &mut TaskExecutionRunner) {
            task_executor.run(
                move |TaskExecutionContext {
                          mdns_daemon,
                          configs,
                          event_bus,
                          ip_cache,
                          ..
                      },
                      task_manager| async move {
                    // Since mDNS daemon is started at the point it's created, we set it to None in order to avoid resource waste
                    // Caller of the start_mdns function should guarantee that the daemon exists
                    let mdns_daemon = match mdns_daemon {
                        Some(daemon) => daemon,
                        None => anyhow::bail!("mDNS daemon is not available but mDNS is enabled"),
                    };

                    let result_sender = event_bus.sender();

                    let mdns_query_timeout = configs.mdns_query_timeout;

                    let mut receiver = mdns::mdns_query_scan(mdns_daemon, task_manager, mdns_query_timeout)?;

                    while let Some(result) = receiver.recv().await {
                        // Let the DNS resolver to figure it out
                        // We can send the result directly from here, but there's no harm to let port scanner to check wanted ports for that machine anyway
                        if let MdnsEvent::ServiceResolved { addr, device_name, .. } = &result {
                            ip_cache.write().insert(*addr, Some(device_name.to_owned()));
                        }

                        result_sender.send(result)?;
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

pub struct NetworkScannerStream {
    event_bus: EventBus,
    task_manager: TaskManager,
    mdns_daemon: Option<MdnsDaemon>,
}

impl NetworkScannerStream {
    pub async fn subscribe<T>(&self) -> TypedReceiver<T> {
        self.event_bus.subscribe::<T>()
    }

    pub fn stop(&self) {
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
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct ScannerToggles {
    pub enable_broadcast: bool,
    pub enable_subnet_scan: bool,
    pub enable_zeroconf: bool,
    pub enable_resolve_dns: bool,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub ports: Vec<MaybeNamedPort>,
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

#[derive(Debug, Clone)]
pub enum DnsEvent {
    /// DNS query start
    Start { ip: IpAddr },
    /// DNS query success
    Success { ip: IpAddr, hostname: String },
    /// DNS query failed
    Failed { ip: IpAddr },
}

#[derive(Debug, Clone)]
pub struct TcpKnockWithHost {
    pub tcp_knock: TcpKnockEvent,
    pub host: Option<String>,
}
