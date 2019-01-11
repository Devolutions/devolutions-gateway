extern crate pcap_file;
extern crate packet;

mod config;
mod jet_client;
mod routing_client;
mod transport;

use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{future, future::ok, Future, Stream};
use tokio::runtime::Runtime;
use tokio_tcp::{TcpListener, TcpStream};

use log::{error, info};
use native_tls::Identity;
use url::Url;

use crate::config::Config;
use crate::jet_client::{JetAssociationsMap, JetClient};
use crate::routing_client::Client;
use crate::transport::tcp::TcpTransport;
use crate::transport::{Transport, JetTransport};


const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

fn main() {
    env_logger::init();
    let config = Config::init();
    let url = Url::parse(&config.listener_url()).unwrap();
    let host = url.host_str().unwrap_or("0.0.0.0").to_string();
    let port = url
        .port()
        .map(|port| port.to_string())
        .unwrap_or_else(|| "8080".to_string());

    let mut listener_addr = String::new();
    listener_addr.push_str(&host);
    listener_addr.push_str(":");
    listener_addr.push_str(&port);

    let socket_addr = listener_addr.parse::<SocketAddr>().unwrap();

    let routing_url_opt = match config.routing_url() {
        Some(url) => Some(Url::parse(&url).expect("routing_url is invalid.")),
        None => None,
    };

    // Initialize the various data structures we're going to use in our server.
    let listener = TcpListener::bind(&socket_addr).unwrap();
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    let mut runtime =
        Runtime::new().expect("This should never fails, a runtime is needed by the entire implementation");
    let executor_handle = runtime.executor();

    // Create the TLS acceptor.
    let der = include_bytes!("cert/certificate.p12");
    let cert = Identity::from_pkcs12(der, "").unwrap();
    let tls_acceptor = tokio_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().unwrap());

    info!("Listening for devolutions-jet proxy connections on {}", socket_addr);
    let server = listener.incoming().for_each(move |conn| {
        set_socket_option(&conn);

        let client_fut = if let Some(ref routing_url) = routing_url_opt {
            match routing_url.scheme() {
                "tcp" => {
                    let transport = TcpTransport::new(conn);
                    Client::new(routing_url.clone(), executor_handle.clone()).serve(transport)
                }
                "tls" => {
                    let routing_url_clone = routing_url.clone();
                    let executor_handle_clone = executor_handle.clone();
                    Box::new(
                        tls_acceptor
                            .accept(conn)
                            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
                            .and_then(move |tls_stream| {
                                let transport = TcpTransport::new_tls(tls_stream);
                                Client::new(routing_url_clone, executor_handle_clone).serve(transport)
                            }),
                    ) as Box<Future<Item = (), Error = io::Error> + Send>
                }
                _ => unreachable!(),
            }
        } else {
            JetClient::new(jet_associations.clone(), executor_handle.clone()).serve(JetTransport::new_tcp(conn))
        };

        executor_handle.spawn(client_fut.then(move |res| {
            match res {
                Ok(_) => {}
                Err(e) => error!("Error with client: {}", e),
            }
            future::ok(())
        }));
        ok(())
    });

    runtime.block_on(server.map_err(|_| ())).unwrap();
}

fn set_socket_option(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        error!("set_nodelay on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_keepalive(Some(Duration::from_secs(2))) {
        error!("set_keepalive on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_send_buffer_size(SOCKET_SEND_BUFFER_SIZE) {
        error!("set_send_buffer_size on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_recv_buffer_size(SOCKET_RECV_BUFFER_SIZE) {
        error!("set_recv_buffer_size on TcpStream failed: {}", e);
    }
}

fn build_proxy<T: Transport, U: Transport>(server_transport: T, client_transport: U) -> Box<Future<Item = (), Error = io::Error> + Send> {
    let jet_sink_server = server_transport.message_sink();
    let mut jet_stream_server = server_transport.message_stream();

    let jet_sink_client = client_transport.message_sink();
    let mut jet_stream_client = client_transport.message_stream();

    let interceptor = interceptor::PacketInterceptor::new(jet_stream_server.peer_addr().unwrap(), jet_stream_client.peer_addr().unwrap(), "out.pcap");
    jet_stream_server.set_packet_interceptor(Box::new(interceptor.clone()));
    jet_stream_client.set_packet_interceptor(Box::new(interceptor.clone()));

    // Build future to forward all bytes
    let f1 = jet_stream_server.forward(jet_sink_client);
    let f2 = jet_stream_client.forward(jet_sink_server);

    Box::new(f1.and_then(|(jet_stream, jet_sink)| {
        // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
        let _ = jet_stream.shutdown();
        let _ = jet_sink.shutdown();
        ok((jet_stream, jet_sink))
    })
    .join(f2.and_then(|(jet_stream, jet_sink)| {
        // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
        let _ = jet_stream.shutdown();
        let _ = jet_sink.shutdown();
        ok((jet_stream, jet_sink))
    }))
    .and_then(|((jet_stream_1, jet_sink_1), (jet_stream_2, jet_sink_2))| {
        let server_addr = jet_stream_1
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or("unknown".to_string());
        let client_addr = jet_stream_2
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or("unknown".to_string());
        info!(
            "Proxy result : {} bytes read on {server} and {} bytes written on {client}. {} bytes read on {client} and {} bytes written on {server}",
            jet_stream_1.nb_bytes_read(),
            jet_sink_1.nb_bytes_written(),
            jet_stream_2.nb_bytes_read(),
            jet_sink_2.nb_bytes_written(),
            server = server_addr,
            client = client_addr
        );
        interceptor.close();

        ok(())
    }))
}

mod interceptor {
    use super::*;
    use std::fs::File;
    use pcap_file::{DataLink, PcapHeader, PcapWriter};
    use packet::ether::Builder as BuildEthernet;
    use packet::ip::v6::Builder as BuildV6;
    use packet::builder::Builder;
    use packet::tcp::flag::Flags;
    use crate::transport::PacketInterceptor as Interceptor;
    use packet::ether::Protocol;

    #[derive(Clone)]
    pub struct PacketInterceptor {
        pcap_writer: Arc<Mutex<PcapWriter<File>>>,
        server_addr: SocketAddr,
        client_addr: SocketAddr,
        server_seq: Arc<Mutex<u32>>,
        client_seq: Arc<Mutex<u32>>,
    }

    impl PacketInterceptor {
        pub fn new(server_addr: SocketAddr, client_addr: SocketAddr, pcap_filename: &str) -> Self {
            let header = PcapHeader {
                magic_number: 0xa1b2c3d4,
                version_major: 2,
                version_minor: 4,
                ts_correction: 0,
                ts_accuracy: 0,
                snaplen: 65535,
                datalink: DataLink::ETHERNET,
            };
            let file = File::create(pcap_filename).expect("Error creating file");
            let pcap_writer: PcapWriter<File> = PcapWriter::with_header(header, file).expect("Error creating pcap writer");

            PacketInterceptor {
                server_addr,
                client_addr,
                pcap_writer: Arc::new(Mutex::new(pcap_writer)),
                server_seq: Arc::new(Mutex::new(0)),
                client_seq: Arc::new(Mutex::new(0)),
            }
        }

        pub fn close(self) {}
    }

    impl Interceptor for PacketInterceptor {
        fn on_new_packet(&mut self, source_addr: Option<SocketAddr>, data: &Vec<u8>) {

            let mut server_seq = self.server_seq.lock().unwrap();
            let mut client_seq = self.client_seq.lock().unwrap();


            // Calculate source/dest address, sequence and acknowledge number
            let (source_addr, dest_addr, seq_number, ack_number) =
                if source_addr.unwrap() == self.client_addr {
                    let result = (self.client_addr, self.server_addr, *server_seq, *client_seq);
                    *server_seq += data.len() as u32;
                    result
                }
                else {
                    let result = (self.server_addr, self.client_addr, *client_seq, *server_seq);
                    *client_seq += data.len() as u32;
                    result
                };

            // Build tcpip packet
            let tcpip_packet =
                match (source_addr, dest_addr) {
                    (SocketAddr::V4(source), SocketAddr::V4(dest)) => {
                        BuildEthernet::default()
                            .destination([0x00, 0x15, 0x5D, 0x01, 0x64, 0x04].into()).unwrap()  // 00:15:5D:01:64:04
                            .source([0x00, 0x15, 0x5D, 0x01, 0x64, 0x01].into()).unwrap()   // 00:15:5D:01:64:01
                            .protocol(Protocol::Ipv4).unwrap()
                            .ip().unwrap()
                            .v4().unwrap()
                                .source(*source.ip()).unwrap()
                                .destination(*dest.ip()).unwrap()
                                .ttl(128).unwrap()
                                .tcp().unwrap()
                                    .window(0x7fff).unwrap()
                                    .source(source_addr.port()).unwrap()
                                    .destination(dest_addr.port()).unwrap()
                                    .acknowledgment(ack_number).unwrap()
                                    .sequence(seq_number).unwrap()
                                    .flags(Flags::from_bits_truncate(0x0018)).unwrap()
                                    .payload(data).unwrap()
                                    .build().unwrap()
                    },
                    (SocketAddr::V6(_source), SocketAddr::V6(_dest)) => {
                        BuildV6::default()
                            .build().unwrap()
                    },
                    (_, _) => unreachable!(),
                };


            // Write packet in pcap file
            let since_epoch= std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("Time went backwards");
            let mut pcap_writer = self.pcap_writer.lock().unwrap();
            if let Err(e) = pcap_writer.write(since_epoch.as_secs() as u32, since_epoch.subsec_micros(), tcpip_packet.as_ref()) {
                error!("Error writting pcap file: {}", e);
            }
        }
    }
}


