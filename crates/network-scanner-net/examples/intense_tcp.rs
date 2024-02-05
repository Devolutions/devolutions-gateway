use std::{
    mem::MaybeUninit,
    net::{SocketAddr, SocketAddrV4},
};

use network_scanner_net::socket::AsyncRawSocket;
use socket2::SockAddr;
use tokio::task::JoinHandle;

/// This example needs to be run with a echo server running on a different process
/// ```
/// use tokio::net::TcpListener;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// use std::env;
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".to_string());
///     let listener = TcpListener::bind(&addr).await?;
///     println!("Listening on: {}", addr);
///     loop {
///         let (mut socket, _) = listener.accept().await?;
///         tokio::spawn(async move {
///             let mut buf = vec![0; 1024];
///             // In a loop, read data from the socket and write the data back.
///             loop {
///                 let n = match socket.read(&mut buf).await {
///                     // socket closed
///                     Ok(n) if n == 0 => return,
///                     Ok(n) => n,
///                     Err(e) => {
///                         eprintln!("Failed to read from socket; err = {:?}", e);
///                         return;
///                     }
///                 };
///                 println!("Received {} bytes", n);
///                 // Write the data back
///                 if let Err(e) = socket.write_all(&buf[0..n]).await {
///                     eprintln!("Failed to write to socket; err = {:?}", e);
///                     return;
///                 }
///             }
///         });
///     }
/// }

/// ```
#[tokio::main(flavor = "multi_thread", worker_threads = 12)]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::INFO)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    let mut socket_arr = vec![];
    for _ in 0..100 {
        tracing::info!("Creating socket");
        let socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket_arr.push(socket);
    }

    fn connect_and_write_something(
        mut socket: AsyncRawSocket,
        addr: std::net::SocketAddr,
    ) -> JoinHandle<anyhow::Result<()>> {
        tokio::task::spawn(async move {
            let addr: SockAddr = addr.into();
            socket.connect(&addr).await?;
            let mut buffer = [MaybeUninit::uninit(); 1024];
            for i in 0..1000 {
                let data = format!("hello world {} times", i);
                tracing::info!("Sending: {} from socket {:?}", &data, &socket);
                let write_future = socket.send(data.as_bytes());

                let size = tokio::time::timeout(std::time::Duration::from_secs(1), write_future).await??;

                if size == 0 {
                    return Ok(());
                }

                let recv_future = socket.recv(&mut buffer);
                tokio::time::timeout(std::time::Duration::from_secs(1), recv_future).await??;
                let received = buffer[..size]
                    .iter()
                    .map(|x| unsafe { x.assume_init() })
                    .collect::<Vec<u8>>();
                assert_eq!(received, data.as_bytes());
                tracing::debug!("Received: {}", std::str::from_utf8(&received)?);
            }
            Ok(())
        })
    }

    let mut futures = vec![];
    for socket in socket_arr {
        let addr: SocketAddr = SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080).into();

        let future = connect_and_write_something(socket, addr);
        futures.push(future);
    }

    for future in futures {
        future.await??;
    }

    Ok(())
}
