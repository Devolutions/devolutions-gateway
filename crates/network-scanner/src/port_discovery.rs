use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use network_scanner_net::runtime::Socket2Runtime;
use socket2::SockAddr;

use crate::task_utils::TaskManager;

pub async fn scan_ports(
    ip: impl Into<IpAddr>,
    port: &[u16],
    runtime: Arc<Socket2Runtime>,
    timeout: Duration,
    task_manager: TaskManager,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<PortScanResult>> {
    let ip = ip.into();
    let mut sockets = vec![];
    for p in port {
        let addr = SockAddr::from(SocketAddr::from((ip, *p)));
        let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        sockets.push((socket, addr));
    }

    if port.is_empty() {
        anyhow::bail!("No ports to scan");
    }

    let (sender, receiver) = tokio::sync::mpsc::channel(port.len());
    for (socket, addr) in sockets {
        let sender = sender.clone();
        task_manager.spawn_no_sub_task(async move {
            let connect_future = socket.connect(&addr);
            let addr = addr
                .as_socket()
                .context("failed to scan port: only IPv4/IPv6 addresses are supported")?;

            match tokio::time::timeout(timeout, connect_future).await {
                Ok(Ok(())) => {
                    // Successfully connected to the port
                    sender.send(PortScanResult::Open(addr)).await?;
                }
                Ok(Err(_)) => {
                    // Failed to connect, but not due to a timeout (e.g., port is closed)
                    sender.send(PortScanResult::Closed(addr)).await?;
                }
                Err(_) => {
                    // Operation timed out
                    sender.send(PortScanResult::Timeout(addr)).await?;
                }
            }

            Ok::<(), anyhow::Error>(())
        });
    }

    Ok(receiver)
}

#[derive(Debug)]
pub enum PortScanResult {
    Open(SocketAddr),
    Closed(SocketAddr),
    Timeout(SocketAddr),
}

impl PortScanResult {
    pub fn is_open(&self) -> bool {
        matches!(self, PortScanResult::Open(_))
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, PortScanResult::Closed(_))
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, PortScanResult::Timeout(_))
    }

    pub fn unwrap_open(self) -> SocketAddr {
        match self {
            PortScanResult::Open(addr) => addr,
            _ => panic!("unwrap_open called on non-open result"),
        }
    }
}
