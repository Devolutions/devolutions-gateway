use std::io;

use futures::future::ok;
use futures::{Future, Stream};
use log::info;
use tokio::runtime::TaskExecutor;
use url::Url;

use crate::transport::tcp::TcpTransport;
use crate::transport::Transport;

pub struct Client {
    routing_url: Url,
    _executor_handle: TaskExecutor,
}

impl Client {
    pub fn new(routing_url: Url, executor_handle: TaskExecutor) -> Self {
        Client {
            routing_url,
            _executor_handle: executor_handle,
        }
    }

    pub fn serve<T: 'static + Transport + Send>(
        self,
        client_transport: T,
    ) -> Box<Future<Item = (), Error = io::Error> + Send> {
        let server_conn = TcpTransport::connect(&self.routing_url);

        Box::new(server_conn.and_then(move |server_transport| {
            //build_proxy(server_transport, client_transport)
            let jet_sink_server = server_transport.message_sink();
            let jet_stream_server = server_transport.message_stream();

            let jet_sink_client = client_transport.message_sink();
            let jet_stream_client = client_transport.message_stream();

            // Build future to forward all bytes
            let f1 = jet_stream_server.forward(jet_sink_client);
            let f2 = jet_stream_client.forward(jet_sink_server);

            f1.and_then(|(jet_stream, jet_sink)| {
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

                ok(())
            })
        }))
    }
}
