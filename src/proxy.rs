use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};
use futures::{
    select,
    Future,
    Stream,
    StreamExt,
    Sink,
    FutureExt,
    TryFutureExt
};
use slog_scope::{info, warn};
use spsc_bip_buffer::bip_buffer_with_len;
use crate::{
    config::{Config, Protocol},
    interceptor::{
        pcap::PcapInterceptor, rdp::RdpMessageReader, MessageReader, UnknownMessageReader, WaykMessageReader,
    },
    rdp::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    transport::{Transport, BIP_BUFFER_LEN},
    SESSION_IN_PROGRESS_COUNT,
};
use crate::transport::{JetStreamType, JetSinkType};
use winapi::_core::task::{Context, Poll};
use winapi::_core::pin::Pin;
use winapi::_core::ops::{DerefMut, Deref};

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
                self.build_with_message_reader(
                    server_transport,
                    client_transport,
                    Some(Box::new(WaykMessageReader))
                ).await
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
                ).await
            }
            Protocol::UNKNOWN => {
                warn!("Protocol is unknown. Data received will not be split to get application message.");
                self.build_with_message_reader(
                    server_transport,
                    client_transport,
                    Some(Box::new(UnknownMessageReader))
                ).await
            }
        }
    }

    pub async fn build_with_message_reader<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
        message_reader: Option<Box<dyn MessageReader>>,
    ) -> Result<(), io::Error> {
        let (client_writer, server_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);
        let (server_writer, client_reader) = bip_buffer_with_len(BIP_BUFFER_LEN);

        let server_peer_addr = server_transport.peer_addr().unwrap();
        let client_peer_addr = client_transport.peer_addr().unwrap();
        let (mut jet_stream_server, jet_sink_server) =
            server_transport.split_transport(server_writer, server_reader);
        let (mut jet_stream_client, jet_sink_client) =
            client_transport.split_transport(client_writer, client_reader);

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

            let mut interceptor = PcapInterceptor::new(
                server_peer_addr,
                client_peer_addr,
                path.to_str().expect("path to pcap files must be valid"),
            );

            interceptor.set_message_reader(message_reader);

            jet_stream_server.as_mut().set_packet_interceptor(Box::new(interceptor.clone()));
            jet_stream_client.as_mut().set_packet_interceptor(Box::new(interceptor));
        }

        // Create trait object wrappers to achieve Stream + Sized type
        let jet_stream_server = SizedStream::new(jet_stream_server);
        let jet_stream_client = SizedStream::new(jet_stream_client);
        let jet_sink_client = SizedSink::new(jet_sink_client);
        let jet_sink_server = SizedSink::new(jet_sink_server);

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

struct SizedStream<T> {
    boxed_stream: JetStreamType<T>,
}

impl<T> SizedStream<T> {
    pub fn new(boxed_stream: JetStreamType<T>) -> Self {
        Self { boxed_stream }
    }
}

impl<T> Stream for SizedStream<T> {
    type Item = Result<T, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.boxed_stream.as_mut().poll_next(cx)
    }
}

struct SizedSink<T> {
    boxed_sink: JetSinkType<T>,
}

impl<T> SizedSink<T> {
    pub fn new(boxed_sink: JetSinkType<T>) -> Self {
        Self { boxed_sink }
    }
}

impl<T> Sink<T> for SizedSink<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.boxed_sink.as_mut().poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.boxed_sink.as_mut().start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.boxed_sink.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.boxed_sink).poll_close(cx)
    }
}