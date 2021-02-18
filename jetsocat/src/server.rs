use crate::pipe::{pipe_with_ws, PipeCmd};
use crate::proxy::ProxyConfig;
use anyhow::{Context as _, Result};
use slog::{debug, o};

pub async fn accept(addr: String, pipe: PipeCmd, proxy_cfg: Option<ProxyConfig>, log: slog::Logger) -> Result<()> {
    use crate::utils::ws_connect_async;

    let accept_log = log.new(o!("accept" => addr.clone()));

    debug!(accept_log, "Connecting");
    let (ws_stream, rsp) = ws_connect_async(addr, proxy_cfg).await?;
    debug!(accept_log, "Connected: {:?}", rsp);

    pipe_with_ws(ws_stream, pipe, accept_log)
        .await
        .with_context(|| "Failed to pipe")?;

    Ok(())
}

pub async fn listen(addr: String, pipe: PipeCmd, log: slog::Logger) -> Result<()> {
    use async_tungstenite::tokio::accept_async;
    use tokio::net::TcpListener;

    let listen_log = log.new(o!("listen" => addr.clone()));
    debug!(listen_log, "Bind listener");
    let listener = TcpListener::bind(addr).await?;
    debug!(listen_log, "Ready to accept");

    let (socket, peer_addr) = listener.accept().await?;
    let peer_log = listen_log.new(o!("peer" => peer_addr));
    debug!(peer_log, "Connected to {}", peer_addr);

    let ws_stream = accept_async(socket).await?;

    pipe_with_ws(ws_stream, pipe, peer_log)
        .await
        .with_context(|| "Failed to pipe")?;

    Ok(())
}
