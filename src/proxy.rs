use std::{
    io,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};

use futures::{future::Either, Future, Stream};
use slog_scope::{info, warn};
use spsc_bip_buffer::bip_buffer_with_len;

use crate::{
    config::{Config, Protocol},
    interceptor::{pcap::PcapInterceptor, rdp::RdpMessageReader, UnknownMessageReader, WaykMessageReader},
    transport::{FinishForwardFuture, ForwardFutureResult, Transport, BIP_BUFFER_LEN},
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

            match self.config.protocol() {
                Protocol::WAYK => {
                    info!("WaykMessageReader will be used to interpret application protocol.");
                    interceptor.set_message_reader(WaykMessageReader::get_messages);
                }
                Protocol::RDP => {
                    info!("RdpMessageReader will be used to interpret application protocol");
                    interceptor.set_message_reader(RdpMessageReader::get_messages);
                }
                Protocol::UNKNOWN => {
                    warn!("Protocol is unknown. Data received will not be split to get application message.");
                    interceptor.set_message_reader(UnknownMessageReader::get_messages);
                }
            }

            jet_stream_server.set_packet_interceptor(Box::new(interceptor.clone()));
            jet_stream_client.set_packet_interceptor(Box::new(interceptor.clone()));
        }

        // Build future to forward all bytes
        let f1 = jet_stream_server.forward(jet_sink_client);
        let f2 = jet_stream_client.forward(jet_sink_server);

        SESSION_IN_PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed);

        Box::new(
            f1.select2(f2)
                .map_err(|either| match either {
                    Either::A((e, _)) => e,
                    Either::B((e, _)) => e,
                })
                .and_then(move |either| {
                        let finish_forward_future = match either {
                            Either::A(((jet_stream_server, jet_sink_client), forward_future)) =>
                            Either::A(FinishForwardFuture::new(forward_future).and_then(move |ForwardFutureResult { nb_bytes_read, nb_bytes_written}| {
                                Ok((
                                    jet_stream_server.nb_bytes_read(),
                                    jet_sink_client.nb_bytes_written(),
                                    nb_bytes_read,
                                    nb_bytes_written,
                                ))
                            })),
                            Either::B(((jet_stream_client, jet_sink_server), forward_future)) =>
                            Either::B(FinishForwardFuture::new(forward_future).and_then(move |ForwardFutureResult { nb_bytes_read, nb_bytes_written}| {
                                Ok((
                                    nb_bytes_read,
                                    nb_bytes_written,
                                    jet_stream_client.nb_bytes_read(),
                                    jet_sink_server.nb_bytes_written(),
                                ))
                            })),
                        };

                        finish_forward_future
                })
                .and_then(move |(server_nb_bytes_read, client_nb_bytes_written, client_nb_bytes_read, server_nb_bytes_written) | {
                     info!(
                         "Proxy result : {} bytes read on {server} and {} bytes written on {client}. {} bytes read on {client} and {} bytes written on {server}",
                         server_nb_bytes_read,
                         client_nb_bytes_written,
                         client_nb_bytes_read,
                         server_nb_bytes_written,
                         server = &server_peer_addr,
                         client = &client_peer_addr
                     );

                    Ok(())
                })
                .then(|result| {
                    SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);
                    result
                }),
        )
    }
}
