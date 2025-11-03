use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use futures::TryStreamExt as _;
use ngrok::config::{HttpTunnelBuilder, TcpTunnelBuilder, TunnelBuilder as _};
use ngrok::tunnel::UrlTunnel as _;
use tracing::Instrument as _;

use crate::DgwState;
use crate::config::dto::{NgrokConf, NgrokTunnelConf};
use crate::generic_client::GenericClient;

#[derive(Clone)]
pub struct NgrokSession {
    inner: ngrok::Session,
}

impl NgrokSession {
    pub async fn connect(conf: &NgrokConf) -> anyhow::Result<Self> {
        let mut builder = ngrok::Session::builder().authtoken(&conf.auth_token);

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

        info!("Connecting to ngrok service");

        // Connect the ngrok session
        let session = builder.connect().await.context("connect to ngrok service")?;

        debug!("Connected with success");

        Ok(Self { inner: session })
    }

    // FIXME: Make this function non-async again when the ngrok UX issue is fixed.
    pub async fn configure_endpoint(&self, name: &str, conf: &NgrokTunnelConf) -> NgrokTunnel {
        use ngrok::config::Scheme;

        match conf {
            NgrokTunnelConf::Tcp(tcp_conf) => {
                let mut builder = self.inner.tcp_endpoint().remote_addr(&tcp_conf.remote_addr);

                if let Some(metadata) = &tcp_conf.metadata {
                    builder = builder.metadata(metadata);
                }

                let before_cidrs = builder.clone();

                builder = tcp_conf
                    .allow_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.allow_cidr(cidr));

                builder = tcp_conf
                    .deny_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.deny_cidr(cidr));

                // HACK: Find the subscription plan. This uses ngrok-rs internal API, so it’s not great.
                // Ideally, we could use the `Session` to find out about the subscription plan without dirty tricks.
                match builder
                    .clone()
                    .forwards_to("Devolutions Gateway Subscription probe")
                    .listen()
                    .await
                {
                    // https://ngrok.com/docs/errors/err_ngrok_9017/
                    // "Your account is not authorized to use ip restrictions."
                    Err(ngrok::session::RpcError::Response(e))
                        if e.error_code.as_deref() == Some("ERR_NGROK_9017")
                            || e.error_code.as_deref() == Some("9017") =>
                    {
                        info!(
                            address = tcp_conf.remote_addr,
                            "Detected a ngrok free plan subscription. IP restriction rules are disabled."
                        );

                        // Revert the builder to before applying the CIDR rules.
                        builder = before_cidrs;
                    }
                    _ => {}
                }

                NgrokTunnel {
                    name: name.to_owned(),
                    inner: NgrokTunnelInner::Tcp(builder),
                }
            }
            NgrokTunnelConf::Http(http_conf) => {
                let mut builder = self
                    .inner
                    .http_endpoint()
                    .domain(&http_conf.domain)
                    .scheme(Scheme::HTTPS);

                if let Some(metadata) = &http_conf.metadata {
                    builder = builder.metadata(metadata);
                }

                if let Some(circuit_breaker) = http_conf.circuit_breaker {
                    builder = builder.circuit_breaker(circuit_breaker);
                }

                if matches!(http_conf.compression, Some(true)) {
                    builder = builder.compression();
                }

                let before_cidrs = builder.clone();

                builder = http_conf
                    .allow_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.allow_cidr(cidr));

                builder = http_conf
                    .deny_cidrs
                    .iter()
                    .fold(builder, |builder, cidr| builder.deny_cidr(cidr));

                // HACK: Find the subscription plan. This uses ngrok-rs internal API, so it’s not great.
                // Ideally, we could use the `Session` to find out about the subscription plan without dirty tricks.
                match builder
                    .clone()
                    .forwards_to("Devolutions Gateway Subscription probe")
                    .listen()
                    .await
                {
                    // https://ngrok.com/docs/errors/err_ngrok_9017/
                    // "Your account is not authorized to use ip restrictions."
                    Err(ngrok::session::RpcError::Response(e))
                        if e.error_code.as_deref() == Some("ERR_NGROK_9017")
                            || e.error_code.as_deref() == Some("9017") =>
                    {
                        info!(
                            domain = http_conf.domain,
                            "Detected a ngrok free plan subscription. IP restriction rules are disabled."
                        );

                        // Revert the builder to before applying the CIDR rules.
                        builder = before_cidrs;
                    }
                    _ => {}
                }

                NgrokTunnel {
                    name: name.to_owned(),
                    inner: NgrokTunnelInner::Http(Box::new(builder)),
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
    Http(Box<HttpTunnelBuilder>),
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
                let tunnel = (*builder)
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
                        .credential_store(state.credential_store)
                        .build()
                        .serve()
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
