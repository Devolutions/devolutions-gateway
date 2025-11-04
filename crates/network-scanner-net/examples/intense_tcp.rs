#![allow(unused_crate_dependencies)]

use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

use network_scanner_net::socket::AsyncRawSocket;
use socket2::SockAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

#[tokio::main(flavor = "multi_thread", worker_threads = 12)]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_names(true)
        .init();
    // trace info all args
    let args: Vec<String> = std::env::args().collect();
    tracing::info!("Args: {:?}", std::env::args().collect::<Vec<String>>());
    if args.len() < 4 {
        println!("Usage: {} [server|client] -p <port>", args[0]);
        return Ok(());
    }

    let port = args[args.len() - 1].parse::<u16>()?;
    let addr = format!("127.0.0.1:{port}");
    match args[1].as_str() {
        "server" => {
            tcp_server(&addr).await?;
        }
        "client" => {
            tcp_client().await?;
        }
        _ => {
            println!("Usage: {} [server|client] -p <port>", args[0]);
        }
    }

    Ok(())
}

async fn tcp_client() -> anyhow::Result<()> {
    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    let mut socket_arr = vec![];
    for _ in 0..100 {
        tracing::info!("Creating socket");
        let socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        socket_arr.push(socket);
    }

    fn connect_and_write_something(mut socket: AsyncRawSocket, addr: SocketAddr) -> JoinHandle<anyhow::Result<()>> {
        tokio::task::spawn(async move {
            let addr: SockAddr = addr.into();
            socket.connect(&addr).await?;
            let mut buffer = [MaybeUninit::uninit(); 1024];
            for i in 0..1000 {
                let data = format!("hello world {i} times");
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

    let mut handles = vec![];
    for socket in socket_arr {
        let addr: SocketAddr = SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080).into();

        let handle = connect_and_write_something(socket, addr);
        handles.push(handle);
    }

    for future in handles {
        future.await??;
    }

    Ok(())
}

async fn tcp_server(addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Listening on: {addr}");
    let count = Arc::new(AtomicU32::new(0));
    loop {
        let (mut socket, _) = listener.accept().await?;
        let _now = Instant::now();
        let count = Arc::clone(&count);
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                let n = match socket.read(&mut buf).await {
                    // socket closed
                    Ok(n) => {
                        if n == 0 {
                            println!("Socket closed");
                            return;
                        }
                        n
                    }
                    Err(e) => {
                        eprintln!("Failed to read from socket; err = {e:?}");
                        return;
                    }
                };
                println!("Received {n} bytes");
                // Write the data back
                if let Err(e) = socket.write_all(&buf[0..n]).await {
                    eprintln!("Failed to write to socket; err = {e:?}");
                    return;
                }
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }
}
