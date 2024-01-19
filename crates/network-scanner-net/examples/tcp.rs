use std::mem::MaybeUninit;
use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new()?;
    let mut socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    //create a tcp socket
    let ip = {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let response = resolver.lookup_ip("info.cern.ch").await?;
        let ip = response.iter().next().unwrap();
        ip
    };
    tracing::info!("ip: {}", ip);
    let socket_addr = SocketAddr::from((ip, 80));
    let clone = socket_addr;
    let handle = tokio::task::spawn(async move {
        tracing::info!("connecting to cern using tokio");
        let mut stream = tokio::net::TcpStream::connect(clone).await?; // making sure tokio io runtime does not collide with socket2 runtime
        tracing::info!("conncted to cern using tokio");
        let _ = stream.write(b"GET / HTTP/1.0\r\n\r\n").await?;
        let buf = &mut [0u8; 1024];
        let size = stream.read(buf).await?;
        Ok::<Vec<_>, anyhow::Error>(buf[..size].to_vec())
    }); // making sure tokio io event loop does not collide with socket2 event loop

    let handle_for_raw = tokio::task::spawn(async move {
        tracing::info!("connecting to cern {}", socket_addr);
        socket.connect(&socket2::SockAddr::from(socket_addr)).await?;
        tracing::info!("connected to cern");

        socket.send(b"GET / HTTP/1.0\r\n\r\n").await?;

        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let (size, _) = socket.recv_from(&mut buf).await?;
        let inited = unsafe { init_buf(&mut buf, size) };
        tracing::info!("received: {:?}", String::from_utf8_lossy(inited));
        Ok::<Vec<_>, anyhow::Error>(inited.to_vec())
    });

    let (a, b) = tokio::join!(handle, handle_for_raw);
    let res_tokio = a??;
    let res_raw = b??;
    assert_eq!(res_tokio, res_raw);

    Ok(())
}

unsafe fn init_buf(buf: &mut [MaybeUninit<u8>], size: usize) -> &[u8] {
    let buf = &mut buf[..size];
    std::mem::transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(buf) as _
}
