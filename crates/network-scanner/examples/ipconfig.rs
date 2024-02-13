fn main() -> anyhow::Result<()> {
    let routes = network_scanner::interfaces::get_network_interfaces()?;
    for route in routes {
        println!("{:#?}", route);
    }
    Ok(())
}
