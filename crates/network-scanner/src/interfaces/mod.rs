use network_interface::NetworkInterfaceConfig;

#[rustfmt::skip]
pub use network_interface::{Addr, NetworkInterface, V4IfAddr, V6IfAddr};

pub fn get_network_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
    NetworkInterface::show().map_err(anyhow::Error::from)
}
