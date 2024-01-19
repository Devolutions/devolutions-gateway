use std::{mem::MaybeUninit, net::SocketAddr};

use socket2::{Protocol, SockAddr};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new()?;

    let socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::RAW, Some(Protocol::ICMPV4))?;

    let echo_request: Vec<u8> = vec![
        8, 0, 77, 1, 0, 1, 0, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    ];

    for i in 0..5 {
        let addr = SocketAddr::from((std::net::Ipv4Addr::new(104, 26, 4, 60), 31337)); // a DNS server from OpenDNS in Bulgaria
        socket.send_to(&echo_request, &SockAddr::from(addr)).await?;
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let (size, addr) = socket.recv_from(&mut buf).await?;
        println!("counter = {i} size: {}, addr: {:?}", size, addr);
        println!()
    }

    Ok(())
}
