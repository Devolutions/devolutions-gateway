use std::{mem::MaybeUninit, net::SocketAddr};

use socket2::SockAddr;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new()?;
    let clone = async_runtime.clone();
    tokio::task::spawn(async move {
        let mut socket = clone
            .new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .unwrap();
        let addr = SocketAddr::from((std::net::Ipv4Addr::new(127, 0, 0, 1), 31255));
        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // wait for the other socket to start

        for _ in 0..10 {
            socket.send_to(b"hello", &SockAddr::from(addr)).await.expect("send_to");
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let (size, addr) = socket.recv_from(&mut buf).await.expect("recv_from");
            tracing::info!("size: {}, addr: {:?}", size, addr);
        }
    });

    let mut socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let addr = SocketAddr::from((std::net::Ipv4Addr::new(127, 0, 0, 1), 31255));
    socket.bind(&SockAddr::from(addr))?;

    loop {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let (size, addr) = match socket.recv_from(&mut buf).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("recv_from error: {:?}", e);
                continue;
            }
        };
        let inited = unsafe { init_buf(&mut buf, size) };
        tracing::info!("size: {}, addr: {:?}", size, addr);
        socket.send_to(inited, &addr).await?;
    }
}

unsafe fn init_buf(buf: &mut [MaybeUninit<u8>], size: usize) -> &[u8] {
    let buf = &mut buf[..size];

    std::mem::transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(buf) as _
}
