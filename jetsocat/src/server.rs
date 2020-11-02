use anyhow::Context as _;
use anyhow::Result;
use futures_util::{future, pin_mut, StreamExt};
use slog::*;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use futures_channel::mpsc;

pub async fn accept(addr: String, log: Logger) -> Result<()> {
    let log = log.new(o!("accept" => addr.clone()));

    info!(log, "Connecting");
    let (ws_stream, _) = connect_async(addr).await?;

    pipe_ws_with_pwsh(ws_stream, log)
        .await
        .with_context(|| "Failed to pipe pwsh")?;

    Ok(())
}

pub async fn listen(addr: String, log: Logger) -> Result<()> {
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    let log = log.new(o!("listen" => addr.clone()));

    info!(log, "Bind listener");
    let listener = TcpListener::bind(addr).await?;
    info!(log, "Ready to accept");
    let (socket, peer_addr) = listener.accept().await?;
    let log = log.new(o!("peer" => peer_addr.clone()));
    info!(log, "Connected to {}", peer_addr);

    let ws_stream = accept_async(socket).await?;

    pipe_ws_with_pwsh(ws_stream, log)
        .await
        .with_context(|| "Failed to pipe pwsh")?;

    Ok(())
}

async fn pipe_ws_with_pwsh<S>(ws_stream: WebSocketStream<S>, log: Logger) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt as _;
    use tokio::process::Command;
    use tokio::sync::Mutex;

    let (write, read) = ws_stream.split();

    info!(log, "Spawn powershell process");

    let mut pwsh_handle = Command::new("pwsh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("-sshs")
        .arg("-NoLogo")
        .arg("-NoProfile")
        .spawn()?;

    let (stdout_tx, stdout_rx) = mpsc::unbounded();

    // stdout -> ws
    let stdout = pwsh_handle.stdout.take().expect("stdout");
    tokio::spawn(read_stdout(stdout, stdout_tx, log.clone()));
    let stdout_to_ws = stdout_rx.map(Ok).forward(write);

    // ws -> stdin
    let stdin = Mutex::new(pwsh_handle.stdin.take().expect("stdin"));
    let ws_to_stdin = read.for_each(|msg| async {
        let msg = msg.unwrap();
        let data = msg.into_data();
        stdin.lock().await.write_all(&data).await.unwrap();
    });

    info!(log, "Piping powershell to the websocket");

    pin_mut!(stdout_to_ws, ws_to_stdin);
    future::select(stdout_to_ws, ws_to_stdin).await;

    Ok(())
}

async fn read_stdout(
    mut stdout: tokio::process::ChildStdout,
    tx: mpsc::UnboundedSender<Message>,
    log: Logger,
) -> Result<()> {
    use tokio::io::AsyncReadExt as _;

    loop {
        let mut buf = vec![0; 1024];
        let n = match stdout.read(&mut buf).await {
            Err(e) => {
                error!(log, "Couldn't read from stdin: {}", e);
                break;
            }
            Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);
        tx.unbounded_send(Message::binary(buf))?;
    }

    Ok(())
}
