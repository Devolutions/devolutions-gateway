extern crate byteorder;
extern crate jet_proto;
extern crate uuid;

use std::env;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

const SERVER_DATA: &'static str = "Server Response";
const CLIENT_DATA: &'static str = "Client Request";

fn bin() -> PathBuf {
    let mut me = env::current_exe().unwrap();
    me.pop();
    if me.ends_with("deps") {
        me.pop();
    }
    me.push("devolutions-jet");
    return me;
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

#[test]
fn smoke() {
    let proxy_addr = "127.0.0.1:8080";
    let routing_url = "127.0.0.1:8081";
    let cmd_line_arg = "-urltcp://127.0.0.1:8080";

    //Spawn our proxy and wait for it to come online
    let proxy = Command::new(bin())
        .arg(cmd_line_arg)
        .arg("--routing_url")
        .arg("tcp://127.0.0.1:8081")
        .spawn()
        .unwrap();
    let _proxy = KillOnDrop(proxy);

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
                    stream.write(&data.as_bytes()).unwrap();
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
                    stream.write(&data.as_bytes()).unwrap();

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
