use anyhow::Context as _;
use futures::TryStreamExt as _;
use ngrok::config::TunnelBuilder as _;
use ngrok::tunnel::UrlTunnel as _;
use tracing::Instrument as _;

use crate::generic_client::GenericClient;
use crate::DgwState;

#[derive(Clone)]
pub struct NgrokSession {
    inner: ngrok::Session,
    state: DgwState,
}

impl NgrokSession {
    pub async fn connect(state: DgwState) -> anyhow::Result<Self> {
        info!("Connecting to ngrok service");

        let session = ngrok::Session::builder()
            // Read the token from the NGROK_AUTHTOKEN environment variable
            .authtoken_from_env()
            // Connect the ngrok session
            .connect()
            .await
            .context("connect to ngrok service")?;

        debug!("ngrok session connected");

        Ok(Self { inner: session, state })
    }

    pub async fn run_tcp_endpoint(&self) -> anyhow::Result<()> {
        info!("Start ngrok TCP tunnel…");

        let conf = self.state.conf_handle.get_conf();

        // Start a tunnel with an HTTP edge
        let mut tunnel = self
            .inner
            .tcp_endpoint()
            .forwards_to(conf.hostname.clone())
            .metadata("Devolutions Gateway Tunnel")
            .listen()
            .await
            .context("TCP tunnel listen")?;

        info!(url = tunnel.url(), "Bound TCP ngrok tunnel");

        loop {
            match tunnel.try_next().await {
                Ok(Some(conn)) => {
                    let state = self.state.clone();
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
                            .build()
                            .serve()
                            .instrument(info_span!("generic-client"))
                            .await
                        {
                            error!(error = format!("{e:#}"), "handle_tcp_peer failed");
                        }
                    }
                    .instrument(info_span!("ngrok_tcp", client = %peer_addr));

                    tokio::spawn(fut);
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

        Ok(())
    }

    pub async fn run_http_endpoint(&self) -> anyhow::Result<()> {
        info!("Start ngrok HTTP tunnel…");

        let conf = self.state.conf_handle.get_conf();

        // Start a tunnel with an HTTP edge
        let mut tunnel = self
            .inner
            .http_endpoint()
            .forwards_to(conf.hostname.clone())
            .metadata("Devolutions Gateway Tunnel")
            .listen()
            .await
            .context("HTTP tunnel listen")?;

        info!(url = tunnel.url(), "Bound HTTP ngrok tunnel");

        loop {
            match tunnel.try_next().await {
                Ok(Some(conn)) => {
                    let state = self.state.clone();
                    let peer_addr = conn.remote_addr();

                    let fut = async move {
                        if let Err(e) = crate::listener::handle_http_peer(conn, state, peer_addr).await {
                            error!(error = format!("{e:#}"), "handle_http_peer failed");
                        }
                    }
                    .instrument(info_span!("ngrok_http", client = %peer_addr));

                    tokio::spawn(fut);
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

        Ok(())
    }
}

// fn handle_http_tunnel(mut tunnel: impl UrlTunnel, ) ->
