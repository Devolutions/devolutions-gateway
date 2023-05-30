use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use futures::TryStreamExt as _;
use ngrok::config::{HttpTunnelBuilder, TcpTunnelBuilder, TunnelBuilder as _};
use ngrok::tunnel::UrlTunnel as _;
use tracing::Instrument as _;

use crate::config::dto::{NgrokConf, NgrokTunnelConf};
use crate::generic_client::GenericClient;
use crate::DgwState;

macro_rules! builder_call_opt {
    ($builder:ident . $method:ident ( $ngrok_option:expr ) ) => {{
        if let Some(option) = $ngrok_option {
            $builder.$method(option)
        } else {
            $builder
        }
    }};
}

macro_rules! builder_call_vec {
    ($builder:ident . $method:ident ( $ngrok_option:expr ) ) => {{
        let mut builder = $builder;
        let mut iter = $ngrok_option;
        loop {
            builder = match iter.next() {
                Some(item) => builder.$method(item),
                None => break builder,
            };
        }
    }};
    ($ngrok_option:expr, $builder:ident . $method:ident ( $( $( & )? $field:ident ),+ ) ) => {{
        let mut builder = $builder;
        let mut iter = $ngrok_option.iter();
        loop {
            builder = match iter.next() {
                Some(item) => builder.$method($( & item . $field ),+),
                None => break builder,
            };
        }
    }};
}

macro_rules! builder_call_flag {
    ($builder:ident . $method:ident ( $ngrok_option:expr ) ) => {{
        match $ngrok_option {
            Some(option) if option => $builder.$method(),
            _ => $builder,
        }
    }};
}

#[derive(Clone)]
pub struct NgrokSession {
    inner: ngrok::Session,
}

impl NgrokSession {
    pub async fn connect(conf: &NgrokConf) -> anyhow::Result<Self> {
        info!("Connecting to ngrok service");

        let builder = ngrok::Session::builder().authtoken(&conf.authtoken);
        let builder = builder_call_opt!(builder.heartbeat_interval(conf.heartbeat_interval));
        let builder = builder_call_opt!(builder.heartbeat_tolerance(conf.heartbeat_tolerance));
        let builder = builder_call_opt!(builder.metadata(&conf.metadata));
        let builder = builder_call_opt!(builder.server_addr(&conf.server_addr));

        // Connect the ngrok session
        let session = builder.connect().await.context("connect to ngrok service")?;

        debug!("ngrok session connected");

        Ok(Self { inner: session })
    }

    pub fn configure_endpoint(&self, name: &str, conf: &NgrokTunnelConf) -> NgrokTunnel {
        use ngrok::config::ProxyProto;
        use ngrok::config::Scheme;
        use std::str::FromStr as _;

        match conf {
            NgrokTunnelConf::Tcp(tcp_conf) => {
                let builder = self.inner.tcp_endpoint().remote_addr(&tcp_conf.remote_addr);
                let builder = builder_call_opt!(builder.metadata(&tcp_conf.metadata));
                let builder = builder_call_opt!(builder.proxy_proto(tcp_conf.proxy_proto.map(ProxyProto::from)));
                let builder = builder_call_vec!(builder.allow_cidr(tcp_conf.allow_cidrs.iter()));
                let builder = builder_call_vec!(builder.deny_cidr(tcp_conf.deny_cidrs.iter()));

                NgrokTunnel {
                    name: name.to_owned(),
                    inner: NgrokTunnelInner::Tcp(builder),
                }
            }
            NgrokTunnelConf::Http(http_conf) => {
                let builder = self.inner.http_endpoint().domain(&http_conf.domain);
                let builder = builder_call_opt!(builder.metadata(&http_conf.metadata));
                let builder = builder_call_vec!(http_conf.basic_auth, builder.basic_auth(username, password));
                let builder = builder_call_opt!(builder.circuit_breaker(http_conf.circuit_breaker));
                let builder = builder_call_flag!(builder.compression(http_conf.compression));
                let builder = builder_call_vec!(builder.allow_cidr(http_conf.allow_cidrs.iter()));
                let builder = builder_call_vec!(builder.deny_cidr(http_conf.deny_cidrs.iter()));
                let builder = builder_call_opt!(builder.proxy_proto(http_conf.proxy_proto.map(ProxyProto::from)));
                let builder = builder_call_vec!(builder.scheme(
                    http_conf
                        .schemes
                        .iter()
                        .map(|s| Scheme::from_str(s).unwrap_or(Scheme::HTTPS))
                ));

                NgrokTunnel {
                    name: name.to_owned(),
                    inner: NgrokTunnelInner::Http(builder),
                }
            }
        }
    }
}

// fn handle_http_tunnel(mut tunnel: impl UrlTunnel, ) ->
pub struct NgrokTunnel {
    name: String,
    inner: NgrokTunnelInner,
}

enum NgrokTunnelInner {
    Tcp(TcpTunnelBuilder),
    Http(HttpTunnelBuilder),
}

impl NgrokTunnel {
    pub async fn open(self, state: DgwState) -> anyhow::Result<()> {
        info!(name = self.name, "Open ngrok tunnel…");

        let hostname = state.conf_handle.get_conf().hostname.clone();

        match self.inner {
            NgrokTunnelInner::Tcp(builder) => {
                // Start tunnel with a TCP edge
                let tunnel = builder
                    .forwards_to(hostname)
                    .listen()
                    .await
                    .context("TCP tunnel listen")?;

                debug!(url = tunnel.url(), "Bound TCP ngrok tunnel");

                run_tcp_tunnel(tunnel, state).await;
            }
            NgrokTunnelInner::Http(builder) => {
                // Start tunnel with an HTTP edge
                let tunnel = builder
                    .forwards_to(hostname)
                    .listen()
                    .await
                    .context("HTTP tunnel listen")?;

                debug!(url = tunnel.url(), "Bound HTTP ngrok tunnel");

                run_http_tunnel(tunnel, state).await;
            }
        }

        Ok(())
    }
}

async fn run_tcp_tunnel(mut tunnel: ngrok::tunnel::TcpTunnel, state: DgwState) {
    info!(url = tunnel.url(), "TCP ngrok tunnel started");

    loop {
        match tunnel.try_next().await {
            Ok(Some(conn)) => {
                let state = state.clone();
                let peer_addr = conn.remote_addr();

                let fut = async move {
                    if let Err(e) = GenericClient::builder()
                        .conf(state.conf_handle.get_conf())
                        .client_addr(peer_addr)
                        .client_stream(conn)
                        .token_cache(state.token_cache)
                        .jrl(state.jrl)
                        .sessions(state.sessions)
                        .subscriber_tx(state.subscriber_tx)
                        .active_recordings(state.recordings.active_recordings)
                        .build()
                        .serve()
                        .instrument(info_span!("generic-client"))
                        .await
                    {
                        error!(error = format!("{e:#}"), "handle_tcp_peer failed");
                    }
                }
                .instrument(info_span!("ngrok_tcp", client = %peer_addr));

                ChildTask::spawn(fut).detach();
            }
            Ok(None) => {
                info!(url = tunnel.url(), "Tunnel closed");
                break;
            }
            Err(error) => {
                error!(url = tunnel.url(), %error, "Failed to accept connection");
            }
        }
    }
}

async fn run_http_tunnel(mut tunnel: ngrok::tunnel::HttpTunnel, state: DgwState) {
    info!(url = tunnel.url(), "HTTP ngrok tunnel started");

    loop {
        match tunnel.try_next().await {
            Ok(Some(conn)) => {
                let state = state.clone();
                let peer_addr = conn.remote_addr();

                let fut = async move {
                    if let Err(e) = crate::listener::handle_http_peer(conn, state, peer_addr).await {
                        error!(error = format!("{e:#}"), "handle_http_peer failed");
                    }
                }
                .instrument(info_span!("ngrok_http", client = %peer_addr));

                ChildTask::spawn(fut).detach();
            }
            Ok(None) => {
                info!(url = tunnel.url(), "Tunnel closed");
                break;
            }
            Err(error) => {
                error!(url = tunnel.url(), %error, "Failed to accept connection");
            }
        }
    }
}

pub struct NgrokTunnelTask {
    pub tunnel: NgrokTunnel,
    pub state: DgwState,
}

#[async_trait]
impl Task for NgrokTunnelTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "ngrok tunnel";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        tokio::select! {
            result = self.tunnel.open(self.state) => result,
            _ = shutdown_signal.wait() => Ok(()),
        }
    }
}
