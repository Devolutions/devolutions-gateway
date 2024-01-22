use std::mem::MaybeUninit;
use std::net::ToSocketAddrs;

use network_scanner_net::assume_init;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Context: Both Tokio/Mio and Polling uses the same OS's async IO API,
/// this example shows that it will not be a problem to use both of them in the same program.
/// The event loop managed by Tokio/Mio will not be affected by the raw socket and vice versa.
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new()?;
    let mut socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    //create a tcp socket
    let request = "GET / HTTP/1.0\r\nHost: info.cern.ch\r\n\r\n".to_string();
    let socket_addr = "info.cern.ch:80"
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow::anyhow!("no address found"))?;
    let clone = socket_addr;
    let request_clone = request.clone();

    let handle = tokio::task::spawn(async move {
        tracing::info!("connecting to cern using tokio");
        let mut stream = tokio::net::TcpStream::connect(clone).await?;
        tracing::info!("conncted to cern using tokio");
        let _ = stream.write(request_clone.as_bytes()).await?;
        let buf = &mut [0u8; 1024];
        let size = stream.read(buf).await?;
        Ok::<Vec<_>, anyhow::Error>(buf[..size].to_vec())
    });

    let handle_for_raw = tokio::task::spawn(async move {
        socket.connect(&socket2::SockAddr::from(socket_addr)).await?;
        socket.send(request.as_bytes()).await?;
        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let (size, _) = socket.recv_from(&mut buf).await?;
        let inited = unsafe { assume_init(&buf[..size]) };
        Ok::<Vec<_>, anyhow::Error>(inited.to_vec())
    });

    let (a, b) = tokio::join!(handle, handle_for_raw);
    let res_tokio = a??;
    let res_raw = b??;
    tracing::info!("res_tokio: {:?}", String::from_utf8_lossy(&res_tokio));
    tracing::info!("res_raw: {:?}", String::from_utf8_lossy(&res_raw));

    Ok(())
}
