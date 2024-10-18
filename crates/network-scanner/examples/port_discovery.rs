#![allow(unused_crate_dependencies)]

use std::time::Duration;

use network_scanner::task_utils::TaskManager;

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_names(true)
        .init();

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None).expect("failed to create runtime");

    let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    // let port = 22,80,443,12345,3399,88
    let port = vec![22, 80, 443, 12345, 3399, 88];
    let mut res =
        network_scanner::port_discovery::scan_ports(ip, &port, runtime, Duration::from_secs(5), TaskManager::new())
            .await
            .expect("failed to scan ports");

    while let Some(res) = res.recv().await {
        tracing::warn!("Port scan result: {:?}", res);
    }
}
