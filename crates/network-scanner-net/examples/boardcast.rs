use std::{mem::MaybeUninit, net::SocketAddr};

use socket2::SockAddr;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let async_runtime = network_scanner_net::async_io::AsyncIoRuntime::new()?;
    let mut handle = async_runtime.start_loop()?;

    let socket = handle
        .new_socket(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )
        .await?;

    let echo_request: Vec<u8> = vec![
        8, 0, 77, 1, 0, 1, 0, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    ];

    let addr = SocketAddr::from((std::net::Ipv4Addr::new(192, 168, 1, 255), 0));
    socket.send_to(&echo_request, SockAddr::from(addr)).await?;

    for i in 0..10 {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let (size, addr) = socket.recv_from(&mut buf).await?;
        println!("counter = {i} size: {}, addr: {:?}", size, addr);
        // print buf in hex format
        for i in 0..size {
            print!("{:02x} ", unsafe { buf[i].assume_init() });
        }
        println!()
    }

    Ok(())
}
