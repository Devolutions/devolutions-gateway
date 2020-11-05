use crate::pipe::{pipe_with_ws, PipeCmd};
use anyhow::{Context as _, Result};
use slog::{debug, o};

pub async fn accept(addr: String, pipe: PipeCmd, log: slog::Logger) -> Result<()> {
    use tokio_tungstenite::connect_async;

    let accept_log = log.new(o!("accept" => addr.clone()));
    debug!(accept_log, "Connecting");
    let (ws_stream, rsp) = connect_async(addr).await?;
    debug!(accept_log, "Connected: {:?}", rsp);

    pipe_with_ws(ws_stream, pipe, accept_log)
        .await
        .with_context(|| "Failed to pipe pwsh")?;

    Ok(())
}

pub async fn listen(addr: String, pipe: PipeCmd, log: slog::Logger) -> Result<()> {
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    let listen_log = log.new(o!("listen" => addr.clone()));
    debug!(listen_log, "Bind listener");
    let listener = TcpListener::bind(addr).await?;
    debug!(listen_log, "Ready to accept");

    let (socket, peer_addr) = listener.accept().await?;
    let peer_log = listen_log.new(o!("peer" => peer_addr.clone()));
    debug!(peer_log, "Connected to {}", peer_addr);

    let ws_stream = accept_async(socket).await?;

    pipe_with_ws(ws_stream, pipe, peer_log)
        .await
        .with_context(|| "Failed to pipe pwsh")?;

    Ok(())
}
