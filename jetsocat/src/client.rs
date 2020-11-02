use anyhow::Result;
use futures_channel::mpsc;
use futures_util::{future, pin_mut, StreamExt};
use slog::*;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

pub async fn connect(addr: String, log: Logger) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let log = log.new(o!("connect" => addr.clone()));

    info!(log, "Connecting");
    let (ws_stream, _) = connect_async(addr).await?;
    let (write, read) = ws_stream.split();

    // stdin -> ws
    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx, log.clone()));
    let stdin_to_ws = stdin_rx.map(Ok).forward(write);

    // ws -> stdout
    let ws_to_stdout = read.for_each(|msg| async {
        let msg = msg.unwrap();
        let data = msg.into_data();
        tokio::io::stdout().write_all(&data).await.unwrap();
    });

    info!(log, "Connected and ready");
    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;

    Ok(())
}

async fn read_stdin(tx: mpsc::UnboundedSender<Message>, log: Logger) -> Result<()> {
    use tokio::io::AsyncReadExt as _;

    let mut stdin = tokio::io::stdin();
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
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
