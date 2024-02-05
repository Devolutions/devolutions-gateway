use network_scanner::{broadcast::asynchronous::broadcast, ip_utils::get_subnets};
use network_scanner_net::runtime;
use std::time::Duration;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_thread_names(true)
        .init();

    let runtime = runtime::Socket2Runtime::new(None)?;
    let subnets = get_subnets()?;
    let mut handles = vec![];
    for subnet in subnets {
        tracing::info!("Broadcast: {:?}", subnet.broadcast);
        let runtime = runtime.clone();
        let handle = tokio::spawn(async move {
            let mut stream = broadcast(subnet.broadcast, Duration::from_secs(3), runtime)
                .await
                .unwrap();
            while let Some(addr) = stream.recv().await {
                tracing::info!("Received: {:?}", addr);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }
    Ok(())
}
