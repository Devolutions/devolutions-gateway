#![allow(unused_crate_dependencies)]

use std::time::Duration;

use anyhow::Context;
use network_scanner::scanner::{NetworkScanner, NetworkScannerParams};
use tokio::time::timeout;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .with_thread_names(true)
        .init();

    let params = NetworkScannerParams {
        ports: vec![22, 80, 443, 389, 636],
        ping_interval: 20,
        ping_timeout: 1000,

        broadcast_timeout: 2000,

        port_scan_timeout: 2000,

        netbios_timeout: 1000,
        netbios_interval: 20,

        mdns_query_timeout: 5 * 1000,

        max_wait_time: 10 * 1000,
    };
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let scanner = NetworkScanner::new(params).unwrap();
        let stream = scanner.start()?;
        let stream_clone = stream.clone();
        let now = std::time::Instant::now();
        tokio::task::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Ctrl-C received, stopping network scan");
                stream.stop();
            }
        });
        while let Ok(Some(res)) = timeout(Duration::from_secs(120), stream_clone.recv())
            .await
            .with_context(|| {
                tracing::error!("Failed to receive from stream");
                "Failed to receive from stream"
            })
        {
            tracing::warn!("Result: {:?}", res);
        }
        stream_clone.stop();
        tracing::warn!("Network Scan finished. elapsed: {:?}", now.elapsed());
        anyhow::Result::<()>::Ok(())
    })?;

    tracing::info!("Done");
    Ok(())
}
