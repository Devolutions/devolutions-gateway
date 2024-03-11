use network_scanner::interfaces::get_network_interfaces;



#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_line_number(true)
        .init();
    let res = get_network_interfaces().await?;

    for interface in res {
        tracing::info!("{:?}", interface)
    }
    Ok(())
}