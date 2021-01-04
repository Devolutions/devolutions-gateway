use anyhow::{Context as _, Result};
use async_tungstenite::WebSocketStream;
use futures_channel::mpsc;
use slog::{info, o};
use tokio::process::Command;

#[derive(Debug)]
pub enum PipeCmd {
    ShC(String),
    Cmd(String),
}

pub async fn pipe_with_ws<S>(ws_stream: WebSocketStream<S>, pipe: PipeCmd, log: slog::Logger) -> Result<()>
where
    S: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    use crate::io::{read_and_send, ws_stream_to_writer};
    use futures_util::{future, pin_mut, StreamExt as _};
    use std::process::Stdio;

    info!(log, "Spawn {:?}", pipe);
    let mut pwsh_handle = construct_command(pipe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let (write, read) = ws_stream.split();

    // stdout -> ws
    let stdout_log = log.new(o!("stdout" => "→ ws"));
    let stdout = pwsh_handle.stdout.take().context("pwsh stdout is missing")?;
    let (stdout_tx, stdout_rx) = mpsc::unbounded();
    tokio::spawn(read_and_send(stdout, stdout_tx, stdout_log));
    let stdout_to_ws = stdout_rx.map(Ok).forward(write);

    // stdin <- ws
    let ws_log = log.new(o!("stdin" => "← ws"));
    let stdin = pwsh_handle.stdin.take().context("pwsh stdin is missing")?;
    let ws_to_stdin = ws_stream_to_writer(read, stdin, ws_log);

    info!(log, "Piping with websocket");
    pin_mut!(stdout_to_ws, ws_to_stdin);
    future::select(stdout_to_ws, ws_to_stdin).await;
    info!(log, "Ended");

    Ok(())
}

fn construct_command(pipe: PipeCmd) -> Command {
    match pipe {
        PipeCmd::ShC(command_string) => {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(command_string);
            cmd
        }
        PipeCmd::Cmd(command_string) => {
            if cfg!(target_os = "windows") {
                let mut cmd = Command::new("cmd");
                cmd.arg("/C").arg(command_string);
                cmd
            } else {
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(command_string);
                cmd
            }
        }
    }
}
