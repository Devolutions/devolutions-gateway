use std::time::Duration;

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None).expect("Failed to create runtime");

    let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    // let port = 22,80,443,12345,3399,88
    let port = vec![22, 80, 443, 12345, 3399, 88];
    let res = network_scanner::port_discovery::scan_ports(ip.into(), &port, &runtime, Some(Duration::from_secs(5)))
        .await
        .expect("Failed to scan ports");
    tracing::info!("res: {:?}", res);
}
