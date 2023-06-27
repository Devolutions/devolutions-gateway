use std::time::Duration;

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

#[derive(Clone)]
pub struct NgrokSession {
    inner: ngrok::Session,
}

impl NgrokSession {
    pub async fn connect(conf: &NgrokConf) -> anyhow::Result<Self> {
        info!("Connecting to ngrok service");

        let mut builder = ngrok::Session::builder().authtoken(&conf.authtoken);

        if let Some(heartbeat_interval) = conf.heartbeat_interval {
            builder = builder.heartbeat_interval(Duration::from_secs(heartbeat_interval));
        }

        if let Some(heartbeat_tolerance) = conf.heartbeat_tolerance {
            builder = builder.heartbeat_tolerance(Duration::from_secs(heartbeat_tolerance));
        }

        if let Some(metadata) = &conf.metadata {
            builder = builder.metadata(metadata);
        }

        if let Some(server_addr) = &conf.server_addr {
            builder = builder.server_addr(server_addr);
        }

        // Connect the ngrok session
        let session = builder.connect().await.context("connect to ngrok service")?;

        debug!("ngrok session connected");

        Ok(Self { inner: session })
    }

    pub fn configure_endpoint(&self, name: &str, conf: &NgrokTunnelConf) -> NgrokTunnel {
        use ngrok::config::{ProxyProto, Scheme};
        use std::str::FromStr as _;

        match conf {
            NgrokTunnelConf::Tcp(tcp_conf) => {
                let mut builder = self.inner.tcp_endpoint().remote_addr(&tcp_conf.remote_addr);

                if let Some(metadata) = &tcp_conf.metadata {
                    builder = builder.metadata(metadata);
                }

                if let Some(proxy_proto) = tcp_conf.proxy_proto {
                    builder = builder.proxy_proto(ProxyProto::from(proxy_proto));
                }

                builder = tcp_conf
                    .allow_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.allow_cidr(cidr));

                builder = tcp_conf
                    .deny_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.deny_cidr(cidr));

                NgrokTunnel {
                    name: name.to_owned(),
                    inner: NgrokTunnelInner::Tcp(builder),
                }
            }
            NgrokTunnelConf::Http(http_conf) => {
                let mut builder = self.inner.http_endpoint().domain(&http_conf.domain);

                if let Some(metadata) = &http_conf.metadata {
                    builder = builder.metadata(metadata);
                }

                builder = http_conf.basic_auth.iter().fold(builder, |builder, basic_auth| {
                    builder.basic_auth(&basic_auth.username, &basic_auth.password)
                });

                if let Some(circuit_breaker) = http_conf.circuit_breaker {
                    builder = builder.circuit_breaker(circuit_breaker);
                }

                if matches!(http_conf.compression, Some(true)) {
                    builder = builder.compression();
                }

                builder = http_conf
                    .allow_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.allow_cidr(cidr));

                builder = http_conf
                    .deny_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.deny_cidr(cidr));

                if let Some(proxy_proto) = http_conf.proxy_proto {
                    builder = builder.proxy_proto(ProxyProto::from(proxy_proto));
                }

                builder = http_conf
                    .schemes
                    .iter()
                    .map(|scheme| Scheme::from_str(scheme).unwrap_or(Scheme::HTTPS))
                    .fold(builder, |builder, scheme| builder.scheme(scheme));

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
