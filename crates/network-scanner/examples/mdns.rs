use std::time::Duration;

use network_scanner::{mdns, task_utils::TaskManager};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_thread_names(true)
        .init();

    let mut receiver = mdns::mdns_query_scan(
        mdns::MdnsDaemon::new()?,
        TaskManager::new(),
        Duration::from_secs(20),
        Duration::from_secs(5),
    )?;

    while let Some((ip, server, port, protocol)) = receiver.recv().await {
        tracing::info!("Found: {}:{:?}:{}:{:?}", ip, server, port, protocol);
    }

    Ok(())
}
