#![allow(unused_crate_dependencies)]

use std::time::Duration;

use network_scanner::named_port::{MaybeNamedPort, NamedPort};
use network_scanner::task_utils::TaskManager;
use tracing::info;

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_names(true)
        .init();

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None).expect("failed to create runtime");

    let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let ports: Vec<MaybeNamedPort> = vec![
        NamedPort::Ssh.into(),
        80.into(),
        NamedPort::Https.into(),
        389.into(),
        636.into(),
    ];
    let mut res =
        network_scanner::port_discovery::scan_ports(ip, &ports, runtime, Duration::from_secs(5), TaskManager::new())
            .await
            .expect("failed to scan ports");

    while let Some(event) = res.recv().await {
        info!(?event);
    }
}
