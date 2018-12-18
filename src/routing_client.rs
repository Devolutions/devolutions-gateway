use std::collections::HashMap;
use std::env;
use std::io;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use futures::future::{self, err, ok};
use futures::stream::Forward;
use futures::{Async, AsyncSink, Future, Sink, Stream};
use tokio::runtime::TaskExecutor;
use tokio_tcp::TcpStream;

use ::{JetStream, JetSink};

pub struct Client {
    routing_url: SocketAddr,
    _executor_handle: TaskExecutor,
}

impl Client {
    pub fn new(routing_url: SocketAddr, executor_handle: TaskExecutor) -> Self {
        Client {
            routing_url,
            _executor_handle: executor_handle,
        }
    }

    pub fn serve(self, conn: Arc<Mutex<TcpStream>>) -> Box<Future<Item = (), Error = io::Error> + Send> {
        Box::new(TcpStream::connect(&self.routing_url).and_then(move |stream| {

            // Build future to forward all bytes
            let server_stream = Arc::new(Mutex::new(stream));
            let jet_stream_server = JetStream::new(server_stream.clone());
            let jet_sink_server = JetSink::new(server_stream.clone());

            let jet_stream_client = JetStream::new(conn.clone());
            let jet_sink_client = JetSink::new(conn.clone());

            let f1 = jet_stream_server.forward(jet_sink_client);
            let f2 = jet_stream_client.forward(jet_sink_server);

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
        }))
    }
}
