#![allow(unused_crate_dependencies)]

use std::time::Duration;

use anyhow::Context;
use network_scanner::event_bus::{ScannerEvent, TypedReceiver};
use network_scanner::named_port::{MaybeNamedPort, NamedPort};
use network_scanner::port_discovery::TcpKnockEvent;
use network_scanner::scanner::{DnsEvent, NetworkScanner, NetworkScannerParams, ScannerConfig, ScannerToggles};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_file(false)
        .with_thread_names(true)
        .with_ansi(false)
        .init();

    let ports: Vec<MaybeNamedPort> = vec![
        NamedPort::Ssh.into(),
        80.into(),
        NamedPort::Https.into(),
        389.into(),
        636.into(),
    ];

    let params = NetworkScannerParams {
        config: ScannerConfig {
            ip_ranges: vec![],
            ports,
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
            enable_resolve_dns: true,
            enable_subnet_scan: true,
            enable_zeroconf: true,
        },
    };
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let scanner = NetworkScanner::new(params).unwrap();
        let stream = scanner.start()?;
        let now = std::time::Instant::now();
        tokio::task::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Ctrl-C received, stopping network scan");
            }
        });

        let mut receiver: TypedReceiver<InterestedEvent> = stream.subscribe().await;
        while let Ok(event) = receiver.recv().await.with_context(|| {
            tracing::error!("Failed to receive from stream");
            "Failed to receive from stream"
        }) {
            tracing::info!(?event);
        }

        stream.stop();
        tracing::warn!("Network Scan finished. elapsed: {:?}", now.elapsed());
        anyhow::Result::<()>::Ok(())
    })?;

    tracing::info!("Done");
    Ok(())
}

#[derive(Debug)]
pub enum InterestedEvent {
    Dns(DnsEvent),
    TcpKnock(TcpKnockEvent),
}

impl TryFrom<ScannerEvent> for InterestedEvent {
    type Error = ();

    fn try_from(event: ScannerEvent) -> Result<Self, Self::Error> {
        match event {
            ScannerEvent::Dns(dns) => Ok(InterestedEvent::Dns(dns)),
            ScannerEvent::TcpKnock(tcp_knock) => Ok(InterestedEvent::TcpKnock(tcp_knock)),
            _ => Err(()),
        }
    }
}
