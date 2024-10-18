#![allow(unused_crate_dependencies)]

use std::net::SocketAddr;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    utils::start_server();
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let async_runtime = network_scanner_net::runtime::Socket2Runtime::new(None)?;
    let good_socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let bad_socket = async_runtime.new_socket(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;

    tracing::info!("good_socket: {:?}", good_socket);
    tracing::info!("bad_socket: {:?}", bad_socket);

    let available_port = 8080;
    let non_available_port = 12345;

    let available_addr = SocketAddr::from(([127, 0, 0, 1], available_port));
    let non_available_addr = SocketAddr::from(([127, 0, 0, 1], non_available_port));

    let handle = tokio::task::spawn(async move { good_socket.connect(&socket2::SockAddr::from(available_addr)).await });

    let handle2 =
        tokio::task::spawn(async move { bad_socket.connect(&socket2::SockAddr::from(non_available_addr)).await });

    let (a, b) = tokio::join!(handle, handle2);
    // remove the outer error from tokio task
    let a = a?;
    let b = b?;
    tracing::info!("should connect: {:?}", &a);
    tracing::info!("should not connect: {:?}", &b);
    assert!(a.is_ok());
    assert!(b.is_err());
    Ok(())
}

mod utils {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn handle_client(mut stream: TcpStream) {
        // read 20 bytes at a time from stream echoing back to stream
        loop {
            let mut read = [0; 1028];
            match stream.read(&mut read) {
                Ok(n) => {
                    if n == 0 {
                        // connection was closed
                        break;
                    }
                    let _ = stream.write(&read[0..n]).unwrap();
                }
                Err(_) => {
                    return;
                }
            }
        }
    }

    pub(super) fn start_server() {
        thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        thread::spawn(move || {
                            handle_client(stream);
                        });
                    }
                    Err(_) => {
                        // println!("Error");
                    }
                }
            }
        });
    }
}
