use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};
use futures::{future::Either, Future, Stream};
use slog_scope::{info, warn};
use spsc_bip_buffer::bip_buffer_with_len;
use tokio::prelude::FutureExt;
use std::time::Duration;
use crate::{
    config::{Config, Protocol},
    interceptor::{
        pcap::PcapInterceptor, rdp::RdpMessageReader, MessageReader, UnknownMessageReader, WaykMessageReader,
    },
    rdp::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    transport::{Transport, BIP_BUFFER_LEN},
    SESSION_IN_PROGRESS_COUNT,
};

pub struct Proxy {
    config: Arc<Config>,
}

impl Proxy {
    pub fn new(config: Arc<Config>) -> Self {
        Proxy { config }
    }

    pub fn build<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
    ) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        match self.config.protocol() {
            Protocol::WAYK => {
                info!("WaykMessageReader will be used to interpret application protocol.");
                self.build_with_message_reader(server_transport, client_transport, Box::new(WaykMessageReader))
            }
            Protocol::RDP => {
                info!("RdpMessageReader will be used to interpret application protocol");
                self.build_with_message_reader(
                    server_transport,
                    client_transport,
                    Box::new(RdpMessageReader::new(
                        HashMap::new(),
                        DvcManager::with_allowed_channels(vec![RDP8_GRAPHICS_PIPELINE_NAME.to_string()]),
                    )),
                )
            }
            Protocol::UNKNOWN => {
                warn!("Protocol is unknown. Data received will not be split to get application message.");
                self.build_with_message_reader(server_transport, client_transport, Box::new(UnknownMessageReader))
            }
        }
    }

    pub fn build_with_message_reader<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
        message_reader: Box<dyn MessageReader>,
    ) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let (client_writer, server_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);
        let (server_writer, client_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);

        let server_peer_addr = server_transport.peer_addr().unwrap();
        let client_peer_addr = client_transport.peer_addr().unwrap();
        let (mut jet_stream_server, jet_sink_server) = server_transport.split_transport(server_writer, server_reader);
        let (mut jet_stream_client, jet_sink_client) = client_transport.split_transport(client_writer, client_reader);

        if let Some(pcap_files_path) = self.config.pcap_files_path() {
            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                client_peer_addr.ip(),
                client_peer_addr.port(),
                server_peer_addr.ip(),
                server_peer_addr.port(),
                chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S")
            );
            let mut path = PathBuf::from(pcap_files_path);
            path.push(filename);

            let mut interceptor = PcapInterceptor::new(
                server_peer_addr,
                client_peer_addr,
                path.to_str().expect("path to pcap files must be valid"),
            );

            interceptor.set_message_reader(message_reader);

            jet_stream_server.set_packet_interceptor(Box::new(interceptor.clone()));
            jet_stream_client.set_packet_interceptor(Box::new(interceptor.clone()));
        }

        // Build future to forward all bytes
        let f1 = jet_stream_server.forward(jet_sink_client);
        let f2 = jet_stream_client.forward(jet_sink_server);

        SESSION_IN_PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed);

        Box::new(f1.select2(f2)
            .and_then(| either | {
                let forward = match either {
                    Either::A(((_, _), forward_future)) => {
                        slog_scope::info!("Stream server -> Sink client: closed successfully");
                        forward_future
                    },
                    Either::B(((_, _), forward_future)) => {
                        slog_scope::info!("Stream client -> Sink server: closed successfully");
                        forward_future
                    },
                };
                Ok(forward.timeout(Duration::from_secs(1)))
            })
            .or_else(| either_e | {
                let forward = match either_e {
                    Either::A((e, forward_future)) => {
                        slog_scope::info!("Stream server -> Sink client: {}", e);
                        forward_future
                    },
                    Either::B((e, forward_future)) => {
                        slog_scope::info!("Stream client -> Sink server: {}", e);
                        forward_future
                    },
                };
                Ok(forward.timeout(Duration::from_secs(1)))
            })
            .map_err(| e | {
                slog_scope::info!("Remaining forward future failed: {}", e);
                e
            })
            .and_then(| _ | {
                slog_scope::info!("Remaining forward future completed successfully");
                Ok(())
            })
            .then(|result| {
                SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);
                result
            }),
        )
    }
}
