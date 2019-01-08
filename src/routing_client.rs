use std::io;

use futures::future::ok;
use futures::{Future};
use tokio::runtime::TaskExecutor;
use url::Url;

use crate::transport::tcp::TcpTransport;
use crate::transport::Transport;
use crate::build_proxy;

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
            build_proxy(server_transport, client_transport)
        }))
    }
}
