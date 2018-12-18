use std::collections::HashMap;
use std::env;
use std::io;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use futures::future::{err, ok};
use futures::stream::Forward;
use futures::{Async, Future, Stream};
use tokio::runtime::{TaskExecutor};
use tokio::timer::Delay;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::{TcpStream};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use uuid::Uuid;

use jet_proto::{JetPacket, ResponseStatusCode};
use ::{JetStream, JetSink};

pub type JetAssociationsMap = Arc<Mutex<HashMap<Uuid, Arc<Mutex<TcpStream>>>>>;

lazy_static! {
    static ref JET_INSTANCE: Option<String> = { env::var("JET_INSTANCE").ok() };
}

const ACCEPT_REQUEST_TIMEOUT_SEC: u64 = 5 * 60;

pub struct JetClient {
    jet_associations: JetAssociationsMap,
    _executor_handle: TaskExecutor,
}

impl JetClient {
    pub fn new(jet_associations: JetAssociationsMap, executor_handle: TaskExecutor) -> Self {
        JetClient {
            jet_associations,
            _executor_handle: executor_handle,
        }
    }

    pub fn serve(self, conn: Arc<Mutex<TcpStream>>) -> Box<Future<Item = (), Error = io::Error> + Send> {
        let msg_reader = JetMsgReader::new(conn.clone());
        let jet_associations = self.jet_associations.clone();
        let executor_handle = self._executor_handle.clone();

        Box::new(msg_reader.and_then(move |msg| {
            if msg.is_accept() {
                let handle_msg = HandleAcceptJetMsg::new(conn.clone(), msg, jet_associations, executor_handle);
                Box::new(handle_msg) as Box<Future<Item = (), Error = io::Error> + Send>
            } else if msg.is_connect() {
                let handle_msg = HandleConnectJetMsg::new(conn.clone(), msg, jet_associations);
                Box::new(handle_msg.and_then(|(f1, f2)| {
                    f1.and_then(|(jet_stream, jet_sink)| {
                        // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
                        jet_stream.shutdown();
                        jet_sink.shutdown();
                        ok((jet_stream, jet_sink))
                    }).join(f2.and_then(|(jet_stream, jet_sink)| {
                        // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
                        jet_stream.shutdown();
                        jet_sink.shutdown();
                        ok((jet_stream, jet_sink))
                    })).and_then(|((jet_stream_1, jet_sink_1), (jet_stream_2, jet_sink_2))| {
                        let server_addr = jet_stream_1
                            .get_addr()
                            .map(|addr| addr.to_string())
                            .unwrap_or("unknown".to_string());
                        let client_addr = jet_stream_2
                            .get_addr()
                            .map(|addr| addr.to_string())
                            .unwrap_or("unknown".to_string());
                        println!(
                            "Proxied {}/{} bytes between {}/{}.",
                            jet_sink_1.nb_bytes_written(),
                            jet_sink_2.nb_bytes_written(),
                            server_addr,
                            client_addr
                        );
                        info!(
                            "Proxied {}/{} bytes between {}/{}.",
                            jet_sink_1.nb_bytes_written(),
                            jet_sink_2.nb_bytes_written(),
                            server_addr,
                            client_addr
                        );
                        ok(())
                    })
                })) as Box<Future<Item = (), Error = io::Error> + Send>
            } else {
                Box::new(err(error_other("Invalid method"))) as Box<Future<Item = (), Error = io::Error> + Send>
            }
        }))
    }
}

fn error_other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

struct JetMsgReader {
    stream: Arc<Mutex<TcpStream>>,
    data_received: Vec<u8>,
}

impl JetMsgReader {
    fn new(stream: Arc<Mutex<TcpStream>>) -> Self {
        JetMsgReader {
            stream,
            data_received: Vec::new(),
        }
    }
}

impl Future for JetMsgReader {
    type Item = JetPacket;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Ok(mut stream) = self.stream.try_lock() {
            let mut buff = [0u8; 1024];
            let len = try_ready!(stream.poll_read(&mut buff));
            let mut buf = buff.to_vec();
            buf.truncate(len);
            self.data_received.append(&mut buf);

            if self.data_received.len() >= jet_proto::JET_MSG_HEADER_SIZE as usize {
                let mut slice = self.data_received.as_slice();
                let signature = slice.read_u32::<LittleEndian>()?; // signature
                if signature != jet_proto::JET_MSG_SIGNATURE {
                    return Err(error_other(&format!("Invalid JetPacket - Signature = {}.", signature)));
                }

                let msg_len = slice.read_u16::<BigEndian>()?;

                if self.data_received.len() >= msg_len as usize {
                    let mut slice = self.data_received.as_slice();
                    let jet_packet = jet_proto::JetPacket::read_from(&mut slice)?;
                    debug!("jet_packet received: {:?}", jet_packet);
                    Ok(Async::Ready(jet_packet))
                } else {
                    debug!(
                        "Waiting more data: received:{} - needed:{}",
                        self.data_received.len(),
                        msg_len
                    );
                    return Ok(Async::NotReady);
                }
            } else {
                debug!(
                    "Waiting more data: received:{} - needed: at least header length ({})",
                    self.data_received.len(),
                    jet_proto::JET_MSG_HEADER_SIZE
                );
                Ok(Async::NotReady)
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}

struct HandleAcceptJetMsg {
    stream: Arc<Mutex<TcpStream>>,
    request_msg: JetPacket,
    response_msg: Option<JetPacket>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
}

impl HandleAcceptJetMsg {
    fn new(
        stream: Arc<Mutex<TcpStream>>,
        msg: JetPacket,
        jet_associations: JetAssociationsMap,
        executor_handle: TaskExecutor,
    ) -> Self {
        assert!(msg.is_accept());
        HandleAcceptJetMsg {
            stream,
            request_msg: msg,
            response_msg: None,
            jet_associations,
            executor_handle,
        }
    }
}

impl Future for HandleAcceptJetMsg {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if self.response_msg.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let uuid = Uuid::new_v4();
                let mut response_msg = JetPacket::new_response(
                    self.request_msg.flags(),
                    self.request_msg.mask(),
                    ResponseStatusCode::StatusCode200,
                );
                response_msg.set_timeout(Some(ACCEPT_REQUEST_TIMEOUT_SEC as u32));
                response_msg.set_association(Some(uuid.clone()));
                response_msg.set_jet_instance(JET_INSTANCE.clone());
                self.response_msg = Some(response_msg);

                jet_associations.insert(uuid, self.stream.clone());
            } else {
                return Ok(Async::NotReady);
            }
        }

        // We have a response ==> Send response + timeout to remove the server if not used
        if let Ok(mut stream) = self.stream.try_lock() {
            let response_msg = self.response_msg.as_ref().unwrap();
            let mut v = Vec::new();
            response_msg.write_to(&mut v)?;
            try_ready!(stream.poll_write(&v));

            // Start timeout to remove the server if no connect request is received with that UUID
            let association = response_msg.association().unwrap();
            let jet_associations = self.jet_associations.clone();
            let timeout = Delay::new(Instant::now() + Duration::from_secs(ACCEPT_REQUEST_TIMEOUT_SEC));
            self.executor_handle.spawn(timeout.then(move |_| {
                RemoveAssociation::new(jet_associations, association.clone()).then(move |res| {
                    if let Ok(true) = res {
                        info!(
                            "No connect request received with association {}. Association removed!",
                            association
                        );
                    }
                    ok(())
                })
            }));

            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}

struct HandleConnectJetMsg {
    stream: Arc<Mutex<TcpStream>>,
    server_stream: Option<Arc<Mutex<TcpStream>>>,
    request_msg: JetPacket,
    response_msg: Option<JetPacket>,
    jet_associations: JetAssociationsMap,
}

impl HandleConnectJetMsg {
    fn new(stream: Arc<Mutex<TcpStream>>, msg: JetPacket, jet_associations: JetAssociationsMap) -> Self {
        assert!(msg.is_connect());

        HandleConnectJetMsg {
            stream,
            server_stream: None,
            request_msg: msg,
            response_msg: None,
            jet_associations,
        }
    }

    fn send_response(&self, response: &JetPacket) -> Result<Async<usize>, io::Error> {
        if let Ok(mut stream) = self.stream.try_lock() {
            let mut v = Vec::new();
            response.write_to(&mut v)?;
            let len = try_ready!(stream.poll_write(&v));
            Ok(Async::Ready(len))
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl Future for HandleConnectJetMsg {
    type Item = (Forward<JetStream, JetSink>, Forward<JetStream, JetSink>);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        //Validate the request
        if self.request_msg.association().is_none() {
            let response = JetPacket::new_response(
                self.request_msg.flags(),
                self.request_msg.mask(),
                ResponseStatusCode::StatusCode400,
            );
            self.send_response(&response)?;
            return Err(error_other("Invalid connect request: No association provided."));
        }

        // Find the server stream
        if self.server_stream.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let server_stream_opt = jet_associations.remove(&self.request_msg.association().unwrap());

                if let Some(server_stream) = server_stream_opt {
                    self.server_stream = Some(server_stream);
                    self.response_msg = Some(JetPacket::new_response(
                        self.request_msg.flags(),
                        self.request_msg.mask(),
                        ResponseStatusCode::StatusCode200,
                    ));
                } else {
                    self.response_msg = Some(JetPacket::new_response(
                        self.request_msg.flags(),
                        self.request_msg.mask(),
                        ResponseStatusCode::StatusCode400,
                    ));
                    error!(
                        "Invalid association ID received: {}",
                        self.request_msg.association().unwrap()
                    );
                }
            } else {
                return Ok(Async::NotReady);
            }
        }

        // Send response
        try_ready!(self.send_response(self.response_msg.as_ref().unwrap()));

        // If server stream found, start the proxy
        if self.server_stream.is_some() {
            // Build future to forward all bytes
            let server_stream = self.server_stream.take().unwrap();
            let jet_stream_server = JetStream::new(server_stream.clone());
            let jet_sink_server = JetSink::new(server_stream.clone());

            let jet_stream_client = JetStream::new(self.stream.clone());
            let jet_sink_client = JetSink::new(self.stream.clone());

            Ok(Async::Ready((
                jet_stream_server.forward(jet_sink_client),
                jet_stream_client.forward(jet_sink_server),
            )))
        } else {
            Err(error_other(&format!(
                "Invalid association ID received: {}",
                self.request_msg.association().unwrap()
            )))
        }
    }
}

struct RemoveAssociation {
    jet_associations: JetAssociationsMap,
    association: Uuid,
}

impl RemoveAssociation {
    fn new(jet_associations: JetAssociationsMap, association: Uuid) -> Self {
        RemoveAssociation {
            jet_associations,
            association,
        }
    }
}

impl Future for RemoveAssociation {
    type Item = bool;
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
            let removed = jet_associations.remove(&self.association).is_some();
            Ok(Async::Ready(removed))
        } else {
            Ok(Async::NotReady)
        }
    }
}