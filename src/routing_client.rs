use std::io;

use futures::future::ok;
use futures::{Future, Stream};
use tokio::runtime::TaskExecutor;

use transport::tcp::TcpTransport;
use transport::Transport;
use url::Url;

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
            let jet_sink_server = server_transport.message_sink();
            let jet_stream_server = server_transport.message_stream();

            let jet_sink_client = client_transport.message_sink();
            let jet_stream_client = client_transport.message_stream();

            // Build future to forward all bytes
            let f1 = jet_stream_server.forward(jet_sink_client);
            let f2 = jet_stream_client.forward(jet_sink_server);

            f1.and_then(|(jet_stream, jet_sink)| {
                // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
                //jet_stream.shutdown();
                //jet_sink.shutdown();
                ok((jet_stream, jet_sink))
            })
            .join(f2.and_then(|(jet_stream, jet_sink)| {
                // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
                //jet_stream.shutdown();
                //jet_sink.shutdown();
                ok((jet_stream, jet_sink))
            }))
            .and_then(|((_jet_stream_1, _jet_sink_1), (_jet_stream_2, _jet_sink_2))| {
                /*let server_addr = jet_stream_1
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
                */
                ok(())
            })
        }))
    }
}
