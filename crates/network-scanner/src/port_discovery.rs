use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use network_scanner_net::runtime::Socket2Runtime;
use socket2::SockAddr;

use crate::named_port::{MaybeNamedPort, NamedAddress};
use crate::task_utils::TaskManager;

pub async fn scan_ports(
    ip: impl Into<IpAddr>,
    ports: &[MaybeNamedPort],
    runtime: Arc<Socket2Runtime>,
    timeout: Duration,
    task_manager: TaskManager,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<TcpKnockEvent>> {
    let ip = ip.into();
    let mut sockets = vec![];
    for port in ports {
        let named_addr = NamedAddress::new(ip, port.clone());
        let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        sockets.push((socket, named_addr));
    }

    if ports.is_empty() {
        anyhow::bail!("no port to scan");
    }

    let (sender, receiver) = tokio::sync::mpsc::channel(ports.len());
    for (socket, named_addr) in sockets {
        let sender = sender.clone();
        task_manager.spawn_no_sub_task(async move {
            let sock_addr: SockAddr = named_addr.as_ref().into();
            let connect_future = socket.connect(&sock_addr);

            let NamedAddress { ip, port } = named_addr;

            match tokio::time::timeout(timeout, connect_future).await {
                Ok(Ok(())) => {
                    // Successfully connected to the port
                    sender.send(TcpKnockEvent::Start { ip, port }).await?;
                }
                Ok(Err(_)) => {
                    // Failed to connect, but not due to a timeout (e.g., port is closed)
                    sender
                        .send(TcpKnockEvent::Failed {
                            ip,
                            port,
                            reason: PortScanFailedReason::Rejected,
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

#[derive(Debug, Clone)]
pub enum PortScanFailedReason {
    Rejected,
    TimedOut,
}

#[derive(Debug, Clone)]
pub enum TcpKnockEvent {
    Start {
        ip: IpAddr,
        port: MaybeNamedPort,
    },
    Success {
        ip: IpAddr,
        port: MaybeNamedPort,
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
            TcpKnockEvent::Start { ip, .. } => *ip,
            TcpKnockEvent::Success { ip, .. } => *ip,
            TcpKnockEvent::Failed { ip, .. } => *ip,
        }
    }
}
