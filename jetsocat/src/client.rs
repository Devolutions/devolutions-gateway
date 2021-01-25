use crate::ProxyConfig;
use anyhow::Result;
use futures_channel::mpsc;
use slog::*;

pub async fn connect(addr: String, proxy_cfg: Option<ProxyConfig>, log: Logger) -> Result<()> {
    use crate::io::{read_and_send, ws_stream_to_writer};
    use crate::utils::ws_connect_async;
    use futures_util::StreamExt as _;
    use futures_util::{future, pin_mut};

    let connect_log = log.new(o!("connect" => addr.clone()));
    info!(connect_log, "Connecting");
    let (ws_stream, rsp) = ws_connect_async(addr, proxy_cfg).await?;
    debug!(connect_log, "Connected: {:?}", rsp);
    let (write, read) = ws_stream.split();

    // stdin -> ws
    let stdin_log = connect_log.new(o!("stdin" => "→ ws"));
    let (stdin_tx, stdin_rx) = mpsc::unbounded();
    tokio::spawn(read_and_send(tokio::io::stdin(), stdin_tx, stdin_log));
    let stdin_to_ws = stdin_rx.map(Ok).forward(write);

    // stdout <- ws
    let ws_log = connect_log.new(o!("stdout" => "← ws"));
    let ws_to_stdout = ws_stream_to_writer(read, tokio::io::stdout(), ws_log);

    info!(connect_log, "Connected and ready");
    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
    info!(connect_log, "Ended");

    Ok(())
}
