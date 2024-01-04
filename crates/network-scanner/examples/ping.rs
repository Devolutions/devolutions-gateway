use network_scanner::ping::ping;

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    ping(ip).await.expect("Failed to ping");
}
