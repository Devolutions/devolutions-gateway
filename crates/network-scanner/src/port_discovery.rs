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
) -> anyhow::Result<Vec<std::io::Result<SockAddr>>> {
    let mut sockets = vec![];
    for p in port {
        let addr = SockAddr::from(SocketAddr::from((ip, *p)));
        let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        sockets.push((socket, addr));
    }

    let mut handle_arr = vec![];
    for (socket, addr) in sockets {
        let handle: JoinHandle<std::io::Result<SockAddr>> = tokio::task::spawn(async move {
            tracing::debug!("scanning port: {:?}", addr.as_socket());
            let future = socket.connect(&addr);
            let timeout = timeout.unwrap_or(Duration::from_millis(300));
            tokio::time::timeout(timeout, future)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e))??;

            Ok(addr)
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
