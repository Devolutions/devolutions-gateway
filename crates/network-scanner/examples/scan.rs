#![allow(unused_crate_dependencies)]

use std::time::Duration;

use anyhow::Context;
use network_scanner::scanner::{NetworkScanner, NetworkScannerParams, ScannerConfig, ScannerToggles};
use tokio::time::timeout;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .with_thread_names(true)
        .init();

    let params = NetworkScannerParams {
        config: ScannerConfig {
            ip_ranges: vec![],
            ports: vec![22, 80, 443, 389, 636],
            ping_interval: Duration::from_millis(20),
            ping_timeout: Duration::from_millis(1000),
            broadcast_timeout: Duration::from_millis(2000),
            port_scan_timeout: Duration::from_millis(2000),
            netbios_timeout: Duration::from_millis(1000),
            netbios_interval: Duration::from_millis(20),
            mdns_query_timeout: Duration::from_millis(5 * 1000),
            max_wait_time: Duration::from_millis(10 * 1000),
        },
        toggle: ScannerToggles {
            enable_broadcast: true,
            enable_ping_start: true,
            enable_resolve_dns: true,
            enable_subnet_scan: true,
            enable_zeroconf: true,
        },
    };
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let scanner = NetworkScanner::new(params).unwrap();
        let mut stream = scanner.start()?;
        let now = std::time::Instant::now();
        tokio::task::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Ctrl-C received, stopping network scan");
            }
        });
        while let Ok(Some(res)) = timeout(Duration::from_secs(120), stream.recv()).await.with_context(|| {
            tracing::error!("Failed to receive from stream");
            "Failed to receive from stream"
        }) {
            tracing::warn!("Result: {:?}", res);
        }

        stream.stop();
        tracing::warn!("Network Scan finished. elapsed: {:?}", now.elapsed());
        anyhow::Result::<()>::Ok(())
    })?;

    tracing::info!("Done");
    Ok(())
}
