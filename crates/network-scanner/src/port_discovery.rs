use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use network_scanner_net::runtime::Socket2Runtime;
use socket2::SockAddr;

pub async fn scan_ports(
    ip: IpAddr,
    port: &[u16],
    runtime: &Arc<Socket2Runtime>,
    timeout: Option<Duration>,
) -> anyhow::Result<Vec<Result<SocketAddr, std::io::Error>>> {
    let mut sockets = vec![];
    for p in port {
        let addr = SockAddr::from(SocketAddr::from((ip, *p)));
        let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        sockets.push((socket, addr));
    }

    let mut res_arr = vec![];
    for (socket, addr) in sockets {
        tracing::debug!("scanning port: {:?}", addr.as_socket());
        let future = socket.connect(&addr);
        let timeout = timeout.unwrap_or(Duration::from_millis(300));
        let timout_result = tokio::time::timeout(timeout, future).await;
        tracing::debug!("timout_result: {:?}", timout_result);
        let Ok(res) = timout_result else {
            res_arr.push(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")));
            continue;
        };

        res_arr.push(res.map(|_| addr.as_socket().expect("unreachable: addr is not ipv4 or ipv6")));
    }

    Ok(res_arr)
}
