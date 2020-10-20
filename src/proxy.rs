use crate::{
    config::{Config, Protocol},
    interceptor::{
        pcap::PcapInterceptor, rdp::RdpMessageReader, MessageReader, UnknownMessageReader, WaykMessageReader,
    },
    rdp::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    transport::{Transport, BIP_BUFFER_LEN},
    SESSION_IN_PROGRESS_COUNT,
};
use futures::{future::Either, Future, Stream};
use slog_scope::{info, warn};
use spsc_bip_buffer::bip_buffer_with_len;
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
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
        match self.config.protocol {
            Protocol::WAYK => {
                info!("WaykMessageReader will be used to interpret application protocol.");
                self.build_with_message_reader(server_transport, client_transport, Some(Box::new(WaykMessageReader)))
            }
            Protocol::RDP => {
                info!("RdpMessageReader will be used to interpret application protocol");
                self.build_with_message_reader(
                    server_transport,
                    client_transport,
                    Some(Box::new(RdpMessageReader::new(
                        HashMap::new(),
                        Some(DvcManager::with_allowed_channels(vec![
                            RDP8_GRAPHICS_PIPELINE_NAME.to_string()
                        ])),
                    ))),
                )
            }
            Protocol::UNKNOWN => {
                warn!("Protocol is unknown. Data received will not be split to get application message.");
                self.build_with_message_reader(server_transport, client_transport, Some(Box::new(UnknownMessageReader)))
            }
        }
    }

    pub fn build_with_message_reader<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
        message_reader: Option<Box<dyn MessageReader>>,
    ) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let (client_writer, server_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);
        let (server_writer, client_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);

        let server_peer_addr = server_transport.peer_addr().unwrap();
        let client_peer_addr = client_transport.peer_addr().unwrap();
        let (mut jet_stream_server, jet_sink_server) = server_transport.split_transport(server_writer, server_reader);
        let (mut jet_stream_client, jet_sink_client) = client_transport.split_transport(client_writer, client_reader);

        if let (Some(pcap_files_path), Some(message_reader)) = (self.config.pcap_files_path.as_ref(), message_reader) {
            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                client_peer_addr.ip(),
                client_peer_addr.port(),
                server_peer_addr.ip(),
                server_peer_addr.port(),
                chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
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
            jet_stream_client.set_packet_interceptor(Box::new(interceptor));
        }

        // Build future to forward all bytes
        let f1 = jet_stream_server.forward(jet_sink_client);
        let f2 = jet_stream_client.forward(jet_sink_server);

        SESSION_IN_PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed);

        use futures_03::{
            compat::Future01CompatExt,
            future::{FutureExt, TryFutureExt},
        };

        macro_rules! finish_remaining_forward {
            ( $fut:ident ( $stream_name:literal => $sink_name:literal ) ) => {
                use tokio::prelude::FutureExt;
                match $fut.timeout(std::time::Duration::from_secs(1)).compat().await {
                    Ok(_) => {
                        slog_scope::info!(concat!(
                            "Stream ",
                            $stream_name,
                            " -> Sink ",
                            $sink_name,
                            " (remaining): terminated normally"
                        ));
                    }
                    Err(e) => {
                        slog_scope::warn!(
                            concat!(
                                "Stream ",
                                $stream_name,
                                " -> Sink ",
                                $sink_name,
                                " (remaining): {}"
                            ),
                            e
                        );
                    }
                }
            };
        }

        let fut = async move {
            match f1.select2(f2).compat().await {
                Ok(either) => {
                    match either {
                        Either::A(((_, _), forward)) => {
                            slog_scope::info!("Stream server -> Sink client: terminated normally");
                            finish_remaining_forward!(forward ("client" => "server"));
                        }
                        Either::B(((_, _), forward)) => {
                            slog_scope::info!("Stream client -> Sink server: terminated normally");
                            finish_remaining_forward!(forward ("server" => "client"));
                        }
                    };
                }
                Err(either_e) => match either_e {
                    Either::A((e, forward)) => {
                        slog_scope::warn!("Stream server -> Sink client: {}", e);
                        finish_remaining_forward!(forward ("client" => "server"));
                    }
                    Either::B((e, forward)) => {
                        slog_scope::warn!("Stream client -> Sink server: {}", e);
                        finish_remaining_forward!(forward ("server" => "client"));
                    }
                },
            }

            SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
        .unit_error()
        .boxed()
        .compat()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "select2 failed"));

        Box::new(fut)
    }
}
