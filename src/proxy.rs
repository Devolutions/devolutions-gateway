use std::{io, path::PathBuf, sync::{Arc, atomic::Ordering}};

use futures::{Future, Stream};
use slog_scope::{info, warn};

use crate::{
    config::{Config, Protocol},
    interceptor::{pcap::PcapInterceptor, rdp::RdpMessageReader, UnknownMessageReader, WaykMessageReader},
    transport::Transport,
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
        let jet_sink_server = server_transport.message_sink();
        let mut jet_stream_server = server_transport.message_stream();

        let jet_sink_client = client_transport.message_sink();
        let mut jet_stream_client = client_transport.message_stream();

        if let Some(pcap_files_path) = self.config.pcap_files_path() {
            let server_peer_addr = jet_stream_server.peer_addr().unwrap();
            let client_peer_addr = jet_stream_client.peer_addr().unwrap();

            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                client_peer_addr.ip(),
                client_peer_addr.port(),
                server_peer_addr.ip().to_string(),
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

        Box::new(f1.and_then(|(mut jet_stream, mut jet_sink)| {
            // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
            let _ = jet_stream.shutdown();
            let _ = jet_sink.shutdown();

            Ok((jet_stream, jet_sink))
        })
            .join(f2.and_then(|(mut jet_stream, mut jet_sink)| {
                // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
                let _ = jet_stream.shutdown();
                let _ = jet_sink.shutdown();

                Ok((jet_stream, jet_sink))
            }))
            .and_then(|((jet_stream_1, jet_sink_1), (jet_stream_2, jet_sink_2))| {
                let server_addr = jet_stream_1
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let client_addr = jet_stream_2
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                info!(
                    "Proxy result : {} bytes read on {server} and {} bytes written on {client}. {} bytes read on {client} and {} bytes written on {server}",
                    jet_stream_1.nb_bytes_read(),
                    jet_sink_1.nb_bytes_written(),
                    jet_stream_2.nb_bytes_read(),
                    jet_sink_2.nb_bytes_written(),
                    server = &server_addr,
                    client = &client_addr
                );

                Ok(())
            }).then(|result| {
            SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);
            result
        }))
    }
}
