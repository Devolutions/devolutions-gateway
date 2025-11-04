#![allow(unused_crate_dependencies)]
#![expect(clippy::clone_on_ref_ptr, reason = "example code clarity over performance")]

use std::mem::MaybeUninit;
use std::net::SocketAddr;

use network_scanner_net::assume_init;
use socket2::SockAddr;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    let clone = async_runtime.clone();
    tokio::task::spawn(async move {
        let mut socket = clone
            .new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .unwrap();
        let addr = SocketAddr::from((std::net::Ipv4Addr::new(127, 0, 0, 1), 31255));
        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // wait for the other socket to start
        tracing::info!("starting to send");
        for i in 0..10 {
            socket.send_to(b"hello", &SockAddr::from(addr)).await.expect("send_to");
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let (size, addr) = socket.recv_from(&mut buf).await.expect("recv_from");
            tracing::info!("size: {}, addr: {:?}, counter: {}", size, addr, i);
        }
    });

    let mut socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let addr = SocketAddr::from((std::net::Ipv4Addr::new(127, 0, 0, 1), 31255));
    socket.bind(&SockAddr::from(addr))?;

    tracing::info!("starting to receive");
    let mut counter = 0;
    loop {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];

        let (size, addr) = match socket.recv_from(&mut buf).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("recv_from error: {:?}", e);
                continue;
            }
        };
        let inited = unsafe { assume_init(&buf[..size]) };
        counter += 1;
        if counter == 9 {
            break;
        }
        socket.send_to(inited, &addr).await?;
    }

    Ok(())
}
