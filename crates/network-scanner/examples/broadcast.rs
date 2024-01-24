use futures::StreamExt;
use network_scanner::broadcast::broadcast;
use std::time::Duration;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_thread_names(true)
        .init();

    let ip = std::net::Ipv4Addr::new(192, 168, 1, 255);
    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    {
        let socket = runtime.new_socket(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        let mut stream = broadcast(ip, Some(Duration::from_secs(1)), socket).await?;

        while let Some(result) = stream.next().await {
            match result {
                Ok(res) => {
                    tracing::info!("received result {:?}", &res)
                }
                Err(e) => {
                    if let Some(e) = e.downcast_ref::<std::io::Error>() {
                        // if is timeout, say timeout then break
                        if let std::io::ErrorKind::TimedOut = e.kind() {
                            tracing::info!("timed out");
                            break;
                        }
                    }
                    return Err(e);
                }
            }
        }
    } // drop socket

    Ok(())
}
