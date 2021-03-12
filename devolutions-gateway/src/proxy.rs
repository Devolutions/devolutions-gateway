use crate::config::{Config, Protocol};
use crate::interceptor::pcap::PcapInterceptor;
use crate::interceptor::rdp::RdpMessageReader;
use crate::interceptor::PacketInterceptor;
use crate::interceptor::{MessageReader, UnknownMessageReader, WaykMessageReader};
use crate::rdp::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME};
use crate::transport::{Transport, BIP_BUFFER_LEN};
use crate::SESSION_IN_PROGRESS_COUNT;
use futures::{select, FutureExt, StreamExt};
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

    pub async fn build<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
    ) -> Result<(), io::Error> {
        match self.config.protocol {
            Protocol::WAYK => {
                info!("WaykMessageReader will be used to interpret application protocol.");
                self.build_with_message_reader(server_transport, client_transport, Some(Box::new(WaykMessageReader)))
                    .await
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
                .await
            }
            Protocol::UNKNOWN => {
                warn!("Protocol is unknown. Data received will not be split to get application message.");
                self.build_with_message_reader(server_transport, client_transport, Some(Box::new(UnknownMessageReader)))
                    .await
            }
        }
    }

    pub async fn build_with_message_reader<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
        message_reader: Option<Box<dyn MessageReader>>,
    ) -> Result<(), io::Error> {
        let mut interceptor: Option<Box<dyn PacketInterceptor>> = None;
        let server_peer_addr = server_transport.peer_addr().unwrap();
        let client_peer_addr = client_transport.peer_addr().unwrap();

        if let (Some(capture_path), Some(message_reader)) = (self.config.capture_path.as_ref(), message_reader) {
            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                client_peer_addr.ip(),
                client_peer_addr.port(),
                server_peer_addr.ip(),
                server_peer_addr.port(),
                chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
            );
            let mut path = PathBuf::from(capture_path);
            path.push(filename);

            let mut pcap_interceptor = PcapInterceptor::new(
                server_peer_addr,
                client_peer_addr,
                path.to_str().expect("path to pcap files must be valid"),
            );

            pcap_interceptor.set_message_reader(message_reader);
            interceptor = Some(Box::new(pcap_interceptor));
        }

        self.build_with_packet_interceptor(server_transport, client_transport, interceptor)
            .await
    }

    pub async fn build_with_packet_interceptor<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
        packet_interceptor: Option<Box<dyn PacketInterceptor>>,
    ) -> Result<(), io::Error> {
        let (client_writer, server_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);
        let (server_writer, client_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);

        let (mut jet_stream_server, jet_sink_server) = server_transport.split_transport(server_writer, server_reader);
        let (mut jet_stream_client, jet_sink_client) = client_transport.split_transport(client_writer, client_reader);

        if let Some(interceptor) = packet_interceptor {
            jet_stream_server
                .as_mut()
                .set_packet_interceptor(interceptor.boxed_clone());
            jet_stream_client.as_mut().set_packet_interceptor(interceptor);
        }

        // Build future to forward all bytes
        let mut downstream = jet_stream_server.forward(jet_sink_client).fuse();
        let mut upstream = jet_stream_client.forward(jet_sink_server).fuse();

        SESSION_IN_PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed);

        macro_rules! finish_remaining_forward {
            ( $fut:ident ( $stream_name:literal => $sink_name:literal ) ) => {
                match tokio::time::timeout(std::time::Duration::from_secs(1), $fut).await {
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

        select! {
            result = downstream => {
                match result {
                    Ok(()) =>  {
                        slog_scope::info!("Stream server -> Sink client: terminated normally");
                        finish_remaining_forward!(downstream ("client" => "server"));
                    }
                    Err(e) => {
                        slog_scope::warn!("Stream server -> Sink client: {}", e);
                        finish_remaining_forward!(downstream ("client" => "server"));
                    }
                }
            },
            result = upstream => {
                match result {
                    Ok(()) =>  {
                        slog_scope::info!("Stream client -> Sink server: terminated normally");
                        finish_remaining_forward!(upstream ("server" => "client"));
                    }
                    Err(e) => {
                        slog_scope::warn!("Stream client -> Sink server: {}", e);
                        finish_remaining_forward!(upstream ("server" => "client"));
                    }
                }
            },
        };

        SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);

        Ok(())
    }
}
