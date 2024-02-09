use std::{mem::MaybeUninit, net::SocketAddr};

use socket2::SockAddr;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    let mut socket = runtime.new_socket(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )?;
    socket.set_broadcast(true)?;

    let echo_request = vec![
        0x08, 0x00, 0x0c, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0xa9, 0x86, 0x20,
    ];

    let addr = SocketAddr::from((std::net::Ipv4Addr::new(192, 168, 50, 255), 0));
    socket.send_to(&echo_request, &SockAddr::from(addr)).await?;

    for i in 0..10 {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let (size, addr) = socket.recv_from(&mut buf).await?;
        tracing::info!("counter = {i} size: {}, addr: {:?}", size, addr.as_socket_ipv4());
    }

    Ok(())
}
