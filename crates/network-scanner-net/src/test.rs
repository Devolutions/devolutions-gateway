use std::{
    io::{ErrorKind, Read, Write},
    mem::MaybeUninit,
    net::{SocketAddr, UdpSocket},
};

use socket2::SockAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socket::AsyncRawSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_connectivity() -> anyhow::Result<()> {
    let addr = local_tcp_server()?;
    let runtime = crate::runtime::Socket2Runtime::new()?;
    let socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    socket.connect(&socket2::SockAddr::from(addr)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_udp() -> anyhow::Result<()> {
    let addr = local_udp_server()?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await; // wait for the other socket to start
    let runtime = crate::runtime::Socket2Runtime::new()?;
    let socket0 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let socket1 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let socket2 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let socket3 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

    fn send_to(mut socket: AsyncRawSocket, number: u8, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move {
            let msg = format!("hello from socket {}", number);
            socket
                .send_to(msg.as_bytes(), &SockAddr::from(addr))
                .await
                .expect("send_to");
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let (size, addr) = socket
                .recv_from(&mut buf)
                .await
                .unwrap_or_else(|_| panic!("recv_from: {}", number));
            tracing::info!("size: {}, addr: {:?}", size, addr);
            let back = unsafe { crate::assume_init(&buf[..size]) };
            assert_eq!(back, format!("hello from socket {}", number).as_bytes());
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
        handle.await?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_tcp() -> anyhow::Result<()> {
    let addr = local_tcp_server()?;
    let runtime = crate::runtime::Socket2Runtime::new()?;
    let socket0 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let socket1 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let socket2 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let socket3 = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;

    fn connect(mut socket: AsyncRawSocket, number: u8, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move {
            socket.connect(&socket2::SockAddr::from(addr)).await.expect("connect");
            let msg = format!("hello from socket {}", number);
            socket.send(msg.as_bytes()).await.expect("send");
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let size = socket.recv(&mut buf).await.expect("recv");
            tracing::info!("size: {}", size);
            let back = unsafe { crate::assume_init(&buf[..size]) };
            assert_eq!(back, format!("hello from socket {}", number).as_bytes());
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
        handle.await?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_with_tokio_tcp() -> anyhow::Result<()> {
    let addr = local_tcp_server()?;
    let runtime = crate::runtime::Socket2Runtime::new()?;
    let mut socket = runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;

    let handle = tokio::task::spawn(async move {
        socket.connect(&socket2::SockAddr::from(addr)).await?;
        let msg = "hello from socket".to_string();
        for _ in 0..10 {
            socket.send(msg.as_bytes()).await?;
            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let size = socket.recv(&mut buf).await?;
            tracing::info!("size: {}", size);
            let back = unsafe { crate::assume_init(&buf[..size]) };
            assert_eq!(back, msg.as_bytes());
        }

        Ok::<(), anyhow::Error>(())
    });

    let handle2 = tokio::task::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let msg = "hello from tokio socket".to_string();
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

    let (a, b) = tokio::join!(handle, handle2);
    a??;
    b??;

    Ok(())
}

fn local_udp_server() -> anyhow::Result<SocketAddr> {
    // Spawn a new thread
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let res = socket.local_addr()?;
    std::thread::spawn(move || {
        // Create and bind the UDP socket

        println!("UDP server listening on {}", socket.local_addr()?);

        let mut buffer = [0u8; 1024]; // A buffer to store incoming data

        loop {
            match socket.recv_from(&mut buffer) {
                Ok((size, src)) => {
                    println!("Received {} bytes from {}", size, src);
                    let socket_clone = socket.try_clone().expect("Failed to clone socket");
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(200)); // simulate some work
                        socket_clone.send_to(&buffer[..size], src).expect("Failed to send data")
                    });
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    tracing::error!("Encountered an error: {}", e);
                    break;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    });
    Ok(res)
}

fn handle_client(mut stream: std::net::TcpStream) -> std::io::Result<()> {
    let mut buffer = [0; 1024];
    loop {
        // Read data from the stream
        let size = stream.read(&mut buffer)?;
        println!("Received {} bytes: {:?}", size, &buffer[..size]);
        std::thread::sleep(std::time::Duration::from_millis(500)); // simulate some work
        stream.write_all(&buffer[..size])?; // Echo the data back to the client
        println!("Echoed back {} bytes", size);
    }
}

fn local_tcp_server() -> anyhow::Result<SocketAddr> {
    // Bind the TCP listener to a local address
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Could not bind TCP listener");
    println!("TCP server listening on {}", listener.local_addr().unwrap());
    let res = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Accept incoming connections
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Spawn a new thread for each connection
                    std::thread::spawn(move || {
                        if let Err(e) = handle_client(stream) {
                            tracing::error!("An error occurred while handling the client: {}", e);
                        }
                    });
                }
                Err(e) => tracing::error!("Connection failed: {}", e),
            }
        }
    });

    Ok(res)
}
