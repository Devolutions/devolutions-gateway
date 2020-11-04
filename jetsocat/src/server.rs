use anyhow::{Context as _, Result};
use futures_channel::mpsc;
use slog::*;
use tokio_tungstenite::WebSocketStream;

pub async fn accept(addr: String, log: Logger) -> Result<()> {
    use tokio_tungstenite::connect_async;

    let accept_log = log.new(o!("accept" => addr.clone()));
    debug!(accept_log, "Connecting");
    let (ws_stream, rsp) = connect_async(addr).await?;
    debug!(accept_log, "Connected: {:?}", rsp);

    pipe_ws_with_pwsh(ws_stream, accept_log)
        .await
        .with_context(|| "Failed to pipe pwsh")?;

    Ok(())
}

pub async fn listen(addr: String, log: Logger) -> Result<()> {
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

    pipe_ws_with_pwsh(ws_stream, peer_log)
        .await
        .with_context(|| "Failed to pipe pwsh")?;

    Ok(())
}

async fn pipe_ws_with_pwsh<S>(ws_stream: WebSocketStream<S>, log: Logger) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::io::{read_and_send, ws_stream_to_writer};
    use futures_util::{future, pin_mut, StreamExt as _};
    use std::process::Stdio;
    use tokio::process::Command;

    info!(log, "Spawn powershell process");
    let mut pwsh_handle = Command::new("pwsh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("-sshs")
        .arg("-NoLogo")
        .arg("-NoProfile")
        .spawn()?;

    let (write, read) = ws_stream.split();

    // stdout -> ws
    let stdout_log = log.new(o!("stdout" => "→ ws"));
    let stdout = pwsh_handle.stdout.take().context("pwsh stdout is missing")?;
    let (stdout_tx, stdout_rx) = mpsc::unbounded();
    tokio::spawn(read_and_send(stdout, stdout_tx, stdout_log));
    let stdout_to_ws = stdout_rx.map(Ok).forward(write);

    // ws -> stdin
    let ws_log = log.new(o!("stdin" => "← ws"));
    let stdin = pwsh_handle.stdin.take().context("pwsh stdin is missing")?;
    let ws_to_stdin = ws_stream_to_writer(read, stdin, ws_log);

    info!(log, "Piping powershell with websocket");
    pin_mut!(stdout_to_ws, ws_to_stdin);
    future::select(stdout_to_ws, ws_to_stdin).await;

    Ok(())
}
