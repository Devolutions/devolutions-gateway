mod common;

use jet_proto::JetMessage;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

use common::run_proxy;
use jet_proto::accept::JetAcceptReq;
use jet_proto::connect::JetConnectReq;
use reqwest::{Client, StatusCode};
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;

const PROXY_ADDR: &str = "127.0.0.1:8080";
const HTTP_URL: &str = "http://127.0.0.1:10256";
const SERVER_DATA: &str = "Server Response";
const CLIENT_DATA: &str = "Client Request";

#[test]
fn smoke_tcp_v1() {
    let proxy_addr = PROXY_ADDR;

    //Spawn our proxy and wait for it to come online
    let _proxy = run_proxy(proxy_addr, None, None, None);

    let (sender_uuid, receiver_uuid) = channel();
    let (sender_end, receiver_end) = channel();

    // Server (method = Accept)
    thread::spawn(move || {
        loop {
            match TcpStream::connect(proxy_addr) {
                Ok(mut stream) => {
                    // Send request
                    let jet_message = JetMessage::JetAcceptReq(JetAcceptReq {
                        version: 1,
                        host: proxy_addr.to_string(),
                        candidate: Uuid::nil(),
                        association: Uuid::nil(),
                    });
                    let mut v: Vec<u8> = Vec::new();
                    jet_message.write_to(&mut v).unwrap();
                    stream.write_all(&v).unwrap();
                    stream.flush().unwrap();

                    // Receive response and get the UUID
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(_n) => {
                                let mut slice: &[u8] = &buffer;
                                let response = JetMessage::read_accept_response(&mut slice).unwrap();
                                match response {
                                    JetMessage::JetAcceptRsp(rsp) => {
                                        assert!(rsp.status_code == 200);
                                        assert!(rsp.association != Uuid::nil());
                                        assert!(rsp.version == 1);
                                        sender_uuid.send(rsp.association).unwrap();
                                    }
                                    _ => {
                                        assert!(false, "Wrong message type received");
                                    }
                                }
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    // Read data sent by client
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(n) => {
                                let mut v = buffer.to_vec();
                                v.truncate(n);
                                let _request = String::from_utf8(v).unwrap();
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    // Send data to server
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
                    let uuid = receiver_uuid.recv().unwrap();

                    // Send request
                    let jet_message = JetMessage::JetConnectReq(JetConnectReq {
                        version: 1,
                        host: proxy_addr.to_string(),
                        association: uuid,
                        candidate: Uuid::nil(),
                    });
                    let mut v: Vec<u8> = Vec::new();
                    jet_message.write_to(&mut v).unwrap();
                    stream.write_all(&v).unwrap();
                    stream.flush().unwrap();

                    // Receive response
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(_n) => {
                                let mut slice: &[u8] = &buffer;
                                let response = JetMessage::read_connect_response(&mut slice).unwrap();
                                match response {
                                    JetMessage::JetConnectRsp(rsp) => {
                                        assert!(rsp.status_code == 200);
                                        assert!(rsp.version == 1);
                                    }
                                    _ => {
                                        assert!(false, "Wrong message type received");
                                    }
                                }
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

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
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    sender_end.send(()).unwrap();
                    thread::sleep(Duration::from_millis(100));
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
    });

    receiver_end.recv().unwrap();
    thread::sleep(Duration::from_millis(100));
}

#[test]
fn smoke_tcp_v2() {
    let proxy_addr = PROXY_ADDR;

    //Spawn our proxy and wait for it to come online
    let _proxy = run_proxy(proxy_addr, None, None, None);

    let (sender_synchro, receiver_synchro) = channel();
    let (sender_end, receiver_end) = channel();

    // Association creation
    let association_id = Uuid::new_v4();
    let client = Client::new();
    let url = HTTP_URL.parse::<Url>().unwrap();
    let create_url = url.join(&format!("/jet/association/{}", association_id)).unwrap();
    assert!(client.post(create_url).send().unwrap().status() == StatusCode::OK);

    // Candidate gathering
    let gather_url = url
        .join(&format!("/jet/association/{}/candidates", association_id))
        .unwrap();
    let mut result = client.post(gather_url).send().unwrap();
    assert!(result.status() == StatusCode::OK);
    let association_info: AssociationInfo = result.json().unwrap();
    assert!(Uuid::from_str(&association_info.id).unwrap() == association_id);

    let mut candidate_id_opt = None;
    for candidate in &association_info.candidates {
        if candidate.url.to_lowercase().starts_with("tcp") {
            candidate_id_opt = Some(Uuid::from_str(&candidate.id).unwrap());
        }
    }
    let candidate_id = candidate_id_opt.unwrap();

    println!("Association info: {:?}", association_info);
    // Server (method = Accept)
    thread::spawn(move || {
        loop {
            match TcpStream::connect(proxy_addr) {
                Ok(mut stream) => {
                    // Send request
                    let jet_message = JetMessage::JetAcceptReq(JetAcceptReq {
                        version: 2,
                        host: proxy_addr.to_string(),
                        candidate: candidate_id,
                        association: association_id,
                    });
                    let mut v: Vec<u8> = Vec::new();
                    jet_message.write_to(&mut v).unwrap();
                    stream.write_all(&v).unwrap();
                    stream.flush().unwrap();

                    // Receive response and get the UUID
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(_n) => {
                                let mut slice: &[u8] = &buffer;
                                let response = JetMessage::read_accept_response(&mut slice).unwrap();
                                match response {
                                    JetMessage::JetAcceptRsp(rsp) => {
                                        assert!(rsp.status_code == 200);
                                        assert!(rsp.association == Uuid::nil());
                                        assert!(rsp.version == 2);
                                        sender_synchro.send(()).unwrap();
                                    }
                                    _ => {
                                        assert!(false, "Wrong message type received");
                                    }
                                }
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    // Read data sent by client
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(n) => {
                                let mut v = buffer.to_vec();
                                v.truncate(n);
                                let _request = String::from_utf8(v).unwrap();
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    // Send data to server
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
                    let _ = receiver_synchro.recv().unwrap();

                    // Send request
                    let jet_message = JetMessage::JetConnectReq(JetConnectReq {
                        version: 2,
                        host: proxy_addr.to_string(),
                        association: association_id,
                        candidate: candidate_id,
                    });
                    let mut v: Vec<u8> = Vec::new();
                    jet_message.write_to(&mut v).unwrap();
                    stream.write_all(&v).unwrap();
                    stream.flush().unwrap();

                    // Receive response
                    loop {
                        let mut buffer = [0u8; 1024];
                        match stream.read(&mut buffer) {
                            Ok(_n) => {
                                let mut slice: &[u8] = &buffer;
                                let response = JetMessage::read_connect_response(&mut slice).unwrap();
                                match response {
                                    JetMessage::JetConnectRsp(rsp) => {
                                        assert!(rsp.status_code == 200);
                                        assert!(rsp.version == 2);
                                    }
                                    _ => {
                                        assert!(false, "Wrong message type received");
                                    }
                                }
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

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
                                break;
                            }
                            Err(_) => {
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                    }

                    sender_end.send(()).unwrap();
                    thread::sleep(Duration::from_millis(100));
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
    });

    receiver_end.recv().unwrap();
    thread::sleep(Duration::from_millis(100));
}

#[derive(Debug, Serialize, Deserialize)]
struct CandidateInfo {
    id: String,
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AssociationInfo {
    id: String,
    candidates: Vec<CandidateInfo>,
}
