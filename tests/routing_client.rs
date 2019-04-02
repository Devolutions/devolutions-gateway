mod common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use common::run_proxy;

const PROXY_ADDR: &str = "127.0.0.1:8082";
const ROUTING_ADDR: &str = "127.0.0.1:8083";
const SERVER_DATA: &str = "Server Response";
const CLIENT_DATA: &str = "Client Request";

fn construct_routing_url(scheme: &str, addr: &str) -> String {
    format!("{}://{}", scheme, addr)
}

#[test]
fn smoke() {
    let proxy_addr = PROXY_ADDR;
    let routing_url = ROUTING_ADDR;

    //Spawn our proxy and wait for it to come online
    let _proxy = run_proxy(proxy_addr, Some(&construct_routing_url("tcp", routing_url)), None);

    let (sender_end, receiver_end) = channel();

    // Start server listening on forward_url
    thread::spawn(move || {
        loop {
            let listener_addr = routing_url.parse::<SocketAddr>().unwrap();
            let listener = TcpListener::bind(&listener_addr).unwrap();
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    // Read data sent by client
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(n) => {
                                let mut v = buffer.to_vec();
                                v.truncate(n);
                                let request = String::from_utf8(v).unwrap();
                                println!("Received from client: {}", request);
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    // Send data to client
                    let data = SERVER_DATA;
                    stream.write_all(&data.as_bytes()).unwrap();
                    thread::sleep(Duration::from_millis(10));
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
    });

    // Client (method = Connect)
    thread::spawn(move || {
        loop {
            match TcpStream::connect(proxy_addr) {
                Ok(mut stream) => {
                    // Send data to server
                    let data = CLIENT_DATA;
                    stream.write_all(&data.as_bytes()).unwrap();

                    // Read data sent by server
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(n) => {
                                let mut v = buffer.to_vec();
                                v.truncate(n);
                                let response = String::from_utf8(v).unwrap();
                                assert_eq!(response, SERVER_DATA.to_string());
                                println!("Received from server: {}", response);
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    sender_end.send(()).unwrap();
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
    });

    receiver_end.recv().unwrap();
    thread::sleep(Duration::from_millis(100));
}
