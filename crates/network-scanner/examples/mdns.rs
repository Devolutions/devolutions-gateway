use network_scanner::{mdns, task_utils::TaskManager};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
    .with_max_level(tracing::Level::INFO)
    .with_thread_names(true)
    .init();

    let deamon = mdns_sd::ServiceDaemon::new()?;

    let mut receiver = mdns::mdns_query_scan(deamon, TaskManager::new())?;

    while let Some((ip, server, port)) = receiver.recv().await {
        println!("ip: {}, server: {:?}, port: {}", ip, server, port);
    }

    Ok(())
}
