use std::default;

use network_scanner::scanner::{NetworkScanner, NetworkScannerParams};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_file(true)
        .with_line_number(true)
        .with_thread_names(true)
        .init();

    let params = NetworkScannerParams {
        ports: vec![22, 80, 443, 389, 636],
        ..default::Default::default()
    };

    let scanner = NetworkScanner::new(params).unwrap();
    let stream = scanner.start()?;
    let stream_clone = stream.clone();
    let now = std::time::Instant::now();
    while let Some(res) = stream_clone.recv().await {
        tracing::warn!("Result: {:?}", res);
    }

    tracing::info!("Elapsed: {:?}", now.elapsed());
    Ok(())
}
