#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_line_number(true)
        .init();

    let interfaces = network_scanner::interfaces::get_network_interfaces()?;
    for interface in interfaces {
        tracing::info!("{:?}", interface)
    }
    Ok(())
}
