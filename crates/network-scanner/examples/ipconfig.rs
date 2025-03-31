
use anyhow::Context;
use network_scanner::interfaces::{self, get_network_interfaces, Filter};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    
    let interfaces = get_network_interfaces(Filter::default())
        .await
        .context("Failed to get network interfaces")?;

    for interface in interfaces {
        println!("{:#?}", interface);
    }

    Ok(())
}