use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use network_scanner_net::runtime::Socket2Runtime;
use socket2::SockAddr;
use tokio::sync::Semaphore;

use crate::named_port::{MaybeNamedPort, NamedAddress};
use crate::task_utils::TaskManager;

pub async fn scan_ports(
    ip: impl Into<IpAddr>,
    ports: &[MaybeNamedPort],
    runtime: Arc<Socket2Runtime>,
    timeout: Duration,
    max_concurrency: Option<usize>,
    interface_bind: crate::scanner::InterfaceBind,
    task_manager: TaskManager,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<TcpKnockEvent>> {
    let ip = ip.into();
    if ports.is_empty() {
        anyhow::bail!("no port to scan");
    }

    let (sender, receiver) = tokio::sync::mpsc::channel(ports.len());
    let semaphore = max_concurrency.map(|max_concurrency| Arc::new(Semaphore::new(max_concurrency.max(1))));
    for port in ports {
        let runtime = Arc::clone(&runtime);
        let named_addr = NamedAddress::new(ip, port.clone());
        let sender = sender.clone();
        let semaphore = semaphore.clone();
        task_manager.spawn_no_sub_task(async move {
            let _permit = match semaphore {
                Some(semaphore) => Some(semaphore.acquire_owned().await?),
                None => None,
            };
            let sock_addr: SockAddr = named_addr.as_ref().into();
            let socket = runtime.new_socket(sock_addr.domain(), socket2::Type::STREAM, None)?;

            if let Some(idx) = interface_bind.interface_index
                && let Err(error) = socket.bind_to_interface(sock_addr.domain(), idx)
            {
                if interface_bind.strict {
                    anyhow::bail!("failed to bind TCP probe socket to interface {idx}: {error}");
                }
                tracing::warn!(
                    ?error,
                    interface_index = idx.get(),
                    ?ip,
                    "Failed to bind TCP probe socket to interface; falling back to default routing"
                );
            }

            let connect_future = socket.connect(&sock_addr);

            let NamedAddress { ip, port } = named_addr;
            let start_time = Instant::now();

            match tokio::time::timeout(timeout, connect_future).await {
                Ok(Ok(())) => {
                    sender
                        .send(TcpKnockEvent::Success {
                            ip,
                            port,
                            time: start_time.elapsed().as_millis(),
                        })
                        .await?;
                }
                Ok(Err(error)) => {
                    // Failed to connect, but not due to a timeout (e.g., port is closed).
                    // Classify on the OS error kind so callers can distinguish
                    // closed ports from unreachable networks/hosts.
                    sender
                        .send(TcpKnockEvent::Failed {
                            ip,
                            port,
                            reason: PortScanFailedReason::from_io_error(&error),
                        })
                        .await?;
                }
                Err(_) => {
                    // Operation timed out
                    sender
                        .send(TcpKnockEvent::Failed {
                            ip,
                            port,
                            reason: PortScanFailedReason::TimedOut,
                        })
                        .await?;
                }
            }

            Ok::<(), anyhow::Error>(())
        });
    }

    Ok(receiver)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortScanFailedReason {
    Rejected,
    TimedOut,
    ConnectionRefused,
    HostUnreachable,
    NetworkUnreachable,
    Other,
}

impl PortScanFailedReason {
    /// Best-effort classification from a connect-time `std::io::Error`.
    pub fn from_io_error(error: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::HostUnreachable => Self::HostUnreachable,
            ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Other,
        }
    }

    /// Stable wire/log code for use in JSON responses and traces.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::TimedOut => "timed_out",
            Self::ConnectionRefused => "connection_refused",
            Self::HostUnreachable => "host_unreachable",
            Self::NetworkUnreachable => "network_unreachable",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub enum TcpKnockEvent {
    Success {
        ip: IpAddr,
        port: MaybeNamedPort,
        time: u128,
    },
    Failed {
        ip: IpAddr,
        port: MaybeNamedPort,
        reason: PortScanFailedReason,
    },
}

impl TcpKnockEvent {
    pub fn ip(&self) -> IpAddr {
        match self {
            TcpKnockEvent::Success { ip, .. } | TcpKnockEvent::Failed { ip, .. } => *ip,
        }
    }
}
