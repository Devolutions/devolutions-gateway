#![expect(clippy::undocumented_unsafe_blocks, reason = "test code with known safety properties")]
#![expect(clippy::clone_on_ref_ptr, reason = "test code clarity over performance")]

use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use socket2::SockAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use crate::socket::AsyncRawSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_udp() -> anyhow::Result<()> {
    let addr = local_udp_server()?;
    tokio::time::sleep(Duration::from_millis(200)).await; // wait for the other socket to start
    let runtime = crate::runtime::Socket2Runtime::new(None)?;
    let socket0 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let socket1 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let socket2 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let socket3 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

    fn send_to(mut socket: AsyncRawSocket, number: u8, addr: SocketAddr) -> JoinHandle<Result<(), anyhow::Error>> {
        tokio::task::spawn(async move {
            let msg = format!("hello from socket {number}");
            socket.send_to(msg.as_bytes(), &SockAddr::from(addr)).await?;

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let (size, addr) = socket.recv_from(&mut buf).await?;

            info!(%size, ?addr);
            let back = unsafe { crate::assume_init(&buf[..size]) };
            assert_eq!(back, format!("hello from socket {number}").as_bytes());
            Ok::<(), anyhow::Error>(())
        })
    }

    //call send_to on all sockets
    let handles = vec![
        send_to(socket0, 0, addr),
        send_to(socket1, 1, addr),
        send_to(socket2, 2, addr),
        send_to(socket3, 3, addr),
    ];

    for handle in handles {
        tokio::time::timeout(Duration::from_secs(10), handle).await???;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connectivity() -> anyhow::Result<()> {
    let kill_server = Arc::new(AtomicBool::new(false));
    let (addr, handle) = local_tcp_server(kill_server.clone()).await?;
    tokio::time::sleep(Duration::from_millis(200)).await; // wait for the other socket to start

    let runtime = crate::runtime::Socket2Runtime::new(None)?;
    let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let addr: SockAddr = addr.into();
    socket.connect(&addr).await?;

    // clean up
    kill_server.store(true, std::sync::atomic::Ordering::Relaxed);
    handle.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn multiple_tcp() -> anyhow::Result<()> {
    let kill_server = Arc::new(AtomicBool::new(false));
    let (addr, handle) = local_tcp_server(kill_server.clone()).await?;
    tokio::time::sleep(Duration::from_millis(200)).await; // wait for the other socket to start

    let runtime = crate::runtime::Socket2Runtime::new(None)?;
    let socket0 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let socket1 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let socket2 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let socket3 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;

    fn connect(mut socket: AsyncRawSocket, number: u8, addr: SocketAddr) -> JoinHandle<Result<(), anyhow::Error>> {
        tokio::task::spawn(async move {
            socket.connect(&SockAddr::from(addr)).await?;
            let msg = format!("hello from socket {number}");
            socket.send(msg.as_bytes()).await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let size = socket.recv(&mut buf).await?;
            tracing::info!("size: {}", size);
            let back = unsafe { crate::assume_init(&buf[..size]) };
            assert_eq!(back, format!("hello from socket {number}").as_bytes());
            Ok::<(), anyhow::Error>(())
        })
    }

    //call send_to on all sockets
    let handles = vec![
        connect(socket0, 0, addr),
        connect(socket1, 1, addr),
        connect(socket2, 2, addr),
        connect(socket3, 3, addr),
    ];

    for handle in handles {
        tokio::time::timeout(Duration::from_secs(5), handle).await???;
    }

    // clean up
    kill_server.store(true, std::sync::atomic::Ordering::Relaxed);
    handle.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_with_tokio_tcp() -> anyhow::Result<()> {
    let kill_server = Arc::new(AtomicBool::new(false));
    let (addr, tcp_handle) = local_tcp_server(kill_server.clone()).await?;
    tokio::time::sleep(Duration::from_millis(200)).await; // wait for the other socket to start

    let runtime = crate::runtime::Socket2Runtime::new(None)?;
    let mut socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;

    let handle = tokio::task::spawn(async move {
        socket.connect(&SockAddr::from(addr)).await?;
        let msg = "hello from socket".to_owned();
        for _ in 0..10 {
            socket.send(msg.as_bytes()).await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let size = socket.recv(&mut buf).await?;
            debug!("size: {}", size);
            let back = unsafe { crate::assume_init(&buf[..size]) };
            assert_eq!(back, msg.as_bytes());
        }

        Ok::<(), anyhow::Error>(())
    });

    let handle2 = tokio::task::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let msg = "hello from tokio socket".to_owned();
        for _ in 0..10 {
            let _ = stream.write(msg.as_bytes()).await?;
            let mut buf = [0u8; 1024];
            let size = stream.read(&mut buf).await?;
            tracing::info!("size: {}", size);
            let back = &buf[..size];
            assert_eq!(back, msg.as_bytes());
        }
        Ok::<(), anyhow::Error>(())
    });

    tokio::time::timeout(Duration::from_secs(5), handle).await???;
    tokio::time::timeout(Duration::from_secs(5), handle2).await???;

    // clean up
    kill_server.store(true, std::sync::atomic::Ordering::Relaxed);
    tcp_handle.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(crate) async fn drop_runtime() -> anyhow::Result<()> {
    {
        let runtime = crate::runtime::Socket2Runtime::new(None)?;

        {
            let bad_socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;

            tracing::info!("bad_socket: {:?}", bad_socket);

            let unused_port = 12345;

            let non_available_addr = SocketAddr::from(([127, 0, 0, 1], unused_port));

            let _ =
                tokio::task::spawn(async move { bad_socket.connect(&SockAddr::from(non_available_addr)).await }).await;
        }

        tracing::info!("runtime arc count: {}", Arc::strong_count(&runtime));
        assert!(Arc::strong_count(&runtime) == 1);
    }

    tracing::info!("runtime should be dropped here");
    Ok(())
}

fn local_udp_server() -> anyhow::Result<SocketAddr> {
    // Spawn a new thread
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let res = socket.local_addr()?;
    std::thread::spawn(move || {
        // Create and bind the UDP socket

        debug!("UDP server listening on {}", socket.local_addr()?);

        let mut buffer = [0u8; 1024]; // A buffer to store incoming data

        loop {
            match socket.recv_from(&mut buffer) {
                Ok((size, src)) => {
                    trace!("Received {} bytes from {}", size, src);
                    let socket_clone = socket.try_clone()?;
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(200)); // simulate some work
                        socket_clone.send_to(&buffer[..size], src)?;
                        Ok::<(), anyhow::Error>(())
                    });
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(error) => {
                    error!(%error, "Failed to read UDP socket");
                    break;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    });
    Ok(res)
}

async fn handle_client(mut stream: tokio::net::TcpStream, awake: Arc<AtomicBool>) -> std::io::Result<()> {
    let mut buffer = [0; 1024];
    loop {
        let read_future = stream.read(&mut buffer);

        let size = match tokio::time::timeout(Duration::from_secs(1), read_future).await {
            Ok(res) => res?,
            Err(_) => {
                if awake.load(std::sync::atomic::Ordering::Relaxed) {
                    return Ok(());
                }
                continue;
            }
        };

        if size == 0 {
            return Ok(());
        }

        debug!("Received {} bytes: {:?}", size, &buffer[..size]);
        std::thread::sleep(Duration::from_millis(200)); // simulate some work
        stream.write_all(&buffer[..size]).await?; // Echo the data back to the client
    }
}

async fn local_tcp_server(
    awake: Arc<AtomicBool>,
) -> anyhow::Result<(SocketAddr, JoinHandle<Result<(), anyhow::Error>>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let res = listener.local_addr()?;
    let handle = tokio::task::spawn(async move {
        loop {
            let listener_future = listener.accept();
            let (stream, _) = match tokio::time::timeout(Duration::from_secs(1), listener_future).await {
                Ok(res) => res,
                Err(_) => {
                    if awake.load(std::sync::atomic::Ordering::Relaxed) {
                        return Ok::<(), anyhow::Error>(());
                    }
                    continue;
                }
            }?;
            let awake = awake.clone();
            tokio::task::spawn(async move {
                if let Err(error) = handle_client(stream, awake).await {
                    error!(%error, "An error occurred while handling the client");
                }
            });
        }
    });
    Ok((res, handle))
}
