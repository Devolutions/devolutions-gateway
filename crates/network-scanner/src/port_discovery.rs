use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use network_scanner_net::runtime::Socket2Runtime;
use socket2::SockAddr;
use tokio::task::JoinHandle;

pub async fn scan_ports(
    ip: IpAddr,
    port: &[u16],
    runtime: &Arc<Socket2Runtime>,
    timeout: Option<Duration>,
) -> anyhow::Result<Vec<PortScanResult>> {
    let mut sockets = vec![];
    for p in port {
        let addr = SockAddr::from(SocketAddr::from((ip, *p)));
        let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        sockets.push((socket, addr));
    }

    let mut handle_arr = vec![];
    for (socket, addr) in sockets {
        let handle: JoinHandle<PortScanResult> = tokio::task::spawn(async move {
            tracing::debug!("scanning port: {:?}", addr.as_socket());
            let future = socket.connect(&addr);
            let timeout = timeout.unwrap_or(Duration::from_millis(500));
            let Ok(result) = tokio::time::timeout(timeout, future).await else {
                return PortScanResult::Timeout(addr);
            };

            let Ok(_) = result else {
                return PortScanResult::Closed(addr);
            };

            PortScanResult::Open(addr)
        });
        handle_arr.push(handle);
    }

    let mut res_arr = vec![];
    for handle in handle_arr {
        let res = handle.await?;
        res_arr.push(res);
    }

    Ok(res_arr)
}

#[derive(Debug)]
pub enum PortScanResult {
    Open(SockAddr),
    Closed(SockAddr),
    Timeout(SockAddr),
}
