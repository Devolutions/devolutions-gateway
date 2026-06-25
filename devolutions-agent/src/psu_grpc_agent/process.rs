use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::psu_grpc_agent::protocol::agent_message::Payload as AgentPayload;
use crate::psu_grpc_agent::protocol::{AgentMessage, ProcessCompleted, ProcessStarted, StartProcess, StreamData};
use crate::psu_grpc_agent::{agent_message, diagnostic, stream_closed, stream_data};

const PWSH_STDIN_CLOSED_EXIT_CODE: i32 = 160;

#[derive(Debug)]
pub(super) struct ProcessControl {
    pub(super) stop: oneshot::Sender<bool>,
}

#[derive(Debug, Default, Clone)]
pub(super) struct ProcessRegistry {
    inner: Arc<Mutex<ProcessRegistryInner>>,
}

#[derive(Debug, Default)]
struct ProcessRegistryInner {
    streams: HashMap<String, mpsc::Sender<StreamData>>,
    processes: HashMap<String, ProcessControl>,
}

impl ProcessRegistry {
    pub(super) async fn register_stream(&self, stream_id: &str) -> mpsc::Receiver<StreamData> {
        let (tx, rx) = mpsc::channel(256);
        self.inner.lock().await.streams.insert(stream_id.to_owned(), tx);
        rx
    }

    pub(super) async fn dispatch_stream_data(&self, stream_data: StreamData) {
        let sender = self.inner.lock().await.streams.get(&stream_data.stream_id).cloned();
        if let Some(sender) = sender {
            let end_of_stream = stream_data.end_of_stream;
            let stream_id = stream_data.stream_id.clone();
            if sender.send(stream_data).await.is_ok() && end_of_stream {
                self.close_stream(&stream_id).await;
            }
        }
    }

    pub(super) async fn close_stream(&self, stream_id: &str) {
        self.inner.lock().await.streams.remove(stream_id);
    }

    pub(super) async fn register_process(&self, correlation_id: String, control: ProcessControl) {
        self.inner.lock().await.processes.insert(correlation_id, control);
    }

    pub(super) async fn stop_process(&self, correlation_id: &str, kill_process: bool) {
        let control = self.inner.lock().await.processes.remove(correlation_id);
        if let Some(control) = control {
            let _ = control.stop.send(kill_process);
        }
    }

    async fn remove_process(&self, correlation_id: &str) {
        self.inner.lock().await.processes.remove(correlation_id);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_process(
    request: StartProcess,
    incoming_rx: mpsc::Receiver<StreamData>,
    mut control_rx: oneshot::Receiver<bool>,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    registry: ProcessRegistry,
    agent_id: String,
    connection_id: String,
    default_executable: String,
) -> anyhow::Result<()> {
    let executable = if request.executable.trim().is_empty() {
        default_executable
    } else {
        request.executable.clone()
    };

    info!(correlation_id = %request.correlation_id, executable = %executable, arguments = ?request.arguments, "Starting PSU gRPC child process");

    let mut command = Command::new(&executable);
    command
        .args(&request.arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if !request.working_directory.trim().is_empty() && std::path::Path::new(&request.working_directory).is_dir() {
        command.current_dir(&request.working_directory);
    }

    for (key, value) in &request.environment {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start PSU gRPC child process using {executable}"))?;
    let process_id_u32 = child.id().unwrap_or(0);
    let process_id = i32::try_from(process_id_u32).unwrap_or(i32::MAX);

    outgoing_tx
        .send(agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::ProcessStarted(ProcessStarted {
                correlation_id: request.correlation_id.clone(),
                process_id,
            }),
        ))
        .await
        .context("failed to send PSU gRPC ProcessStarted message")?;

    let stdin = child.stdin.take().context("child process stdin was not piped")?;
    let stdout = child.stdout.take().context("child process stdout was not piped")?;
    let stderr = child.stderr.take().context("child process stderr was not piped")?;

    let stdout_task = tokio::spawn(pump_stdout_to_server(
        stdout,
        request.stream_id.clone(),
        outgoing_tx.clone(),
        agent_id.clone(),
        connection_id.clone(),
        process_id,
    ));
    let stderr_task = tokio::spawn(pump_stderr_diagnostics(
        stderr,
        outgoing_tx.clone(),
        agent_id.clone(),
        connection_id.clone(),
        process_id,
    ));
    let stdin_task = tokio::spawn(pump_server_to_stdin(incoming_rx, stdin, process_id));
    tokio::pin!(stdin_task);

    let mut stdin_closed_from_end_of_stream = false;
    let mut canceled = false;

    let status = loop {
        tokio::select! {
            status = child.wait() => break status.context("failed to wait for PSU gRPC child process")?,
            stdin_result = &mut stdin_task => {
                stdin_closed_from_end_of_stream = stdin_result.unwrap_or(false);
                info!(process_id, "Finished receiving PSU gRPC stdin data; waiting for graceful child process exit");

                match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                    Ok(status) => break status.context("failed to wait for PSU gRPC child process")?,
                    Err(_) => {
                        warn!(process_id, "PSU gRPC child process did not exit after stdin closed; killing process tree");
                        child.start_kill().context("failed to kill PSU gRPC child process")?;
                        canceled = true;
                    }
                }
            }
            kill_process = &mut control_rx => {
                match kill_process {
                    Ok(true) => {
                        info!(process_id, correlation_id = %request.correlation_id, "Killing PSU gRPC child process on server request");
                        child.start_kill().context("failed to kill PSU gRPC child process")?;
                        canceled = true;
                        break child.wait().await.context("failed to wait for killed PSU gRPC child process")?;
                    }
                    Ok(false) => {
                        info!(process_id, correlation_id = %request.correlation_id, "Graceful stop requested for PSU gRPC child process; waiting for stream shutdown");
                    }
                    Err(_) => {}
                }
            }
        }
    };

    stdout_task.abort();
    stderr_task.abort();

    let exit_code = status.code().unwrap_or(-1);
    if stdin_closed_from_end_of_stream && exit_code == PWSH_STDIN_CLOSED_EXIT_CODE {
        info!(
            process_id,
            exit_code, "PSU gRPC child process exited with expected code after stdin EOF for pwsh -s"
        );
    } else {
        info!(process_id, exit_code, "PSU gRPC child process exited");
    }

    let _ = outgoing_tx
        .send(agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::StreamClosed(stream_closed(
                request.stream_id.clone(),
                "child process completed".to_owned(),
                false,
            )),
        ))
        .await;

    outgoing_tx
        .send(agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::ProcessCompleted(ProcessCompleted {
                correlation_id: request.correlation_id.clone(),
                exit_code,
                canceled,
                error_message: String::new(),
            }),
        ))
        .await
        .context("failed to send PSU gRPC ProcessCompleted message")?;

    registry.close_stream(&request.stream_id).await;
    registry.remove_process(&request.correlation_id).await;

    Ok(())
}

async fn pump_stdout_to_server<R>(
    mut stdout: R,
    stream_id: String,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    agent_id: String,
    connection_id: String,
    process_id: i32,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0u8; 4096];
    let mut line = Vec::new();
    let mut sequence = 0;

    loop {
        let read = stdout.read(&mut buffer).await.context("failed to read child stdout")?;
        if read == 0 {
            break;
        }

        for byte in &buffer[..read] {
            match *byte {
                b'\r' => {}
                b'\n' => {
                    send_stream_frame(
                        &outgoing_tx,
                        &agent_id,
                        &connection_id,
                        &stream_id,
                        sequence,
                        std::mem::take(&mut line),
                        false,
                    )
                    .await?;
                    sequence += 1;
                }
                byte => line.push(byte),
            }
        }
    }

    if !line.is_empty() {
        send_stream_frame(
            &outgoing_tx,
            &agent_id,
            &connection_id,
            &stream_id,
            sequence,
            line,
            false,
        )
        .await?;
        sequence += 1;
    }

    send_stream_frame(
        &outgoing_tx,
        &agent_id,
        &connection_id,
        &stream_id,
        sequence,
        Vec::new(),
        true,
    )
    .await?;
    info!(process_id, stream_id = %stream_id, sequence, "Finished sending PSU gRPC stdout frames");
    Ok(())
}

async fn send_stream_frame(
    outgoing_tx: &mpsc::Sender<AgentMessage>,
    agent_id: &str,
    connection_id: &str,
    stream_id: &str,
    sequence: u64,
    data: Vec<u8>,
    end_of_stream: bool,
) -> anyhow::Result<()> {
    outgoing_tx
        .send(agent_message(
            agent_id,
            connection_id,
            AgentPayload::StreamData(stream_data(stream_id.to_owned(), sequence, data, end_of_stream)),
        ))
        .await
        .context("failed to send PSU gRPC stdout frame")
}

async fn pump_server_to_stdin(
    mut incoming_rx: mpsc::Receiver<StreamData>,
    mut stdin: tokio::process::ChildStdin,
    process_id: i32,
) -> bool {
    let mut closed_from_end_of_stream = false;

    while let Some(frame) = incoming_rx.recv().await {
        if frame.end_of_stream {
            info!(process_id, "Received PSU gRPC stdin end-of-stream; closing child stdin");
            closed_from_end_of_stream = true;
            break;
        }

        let mut data = frame.data;
        if !ends_with_line_ending(&data) {
            data.push(b'\n');
        }

        if let Err(error) = stdin.write_all(&data).await {
            warn!(process_id, %error, "Failed to write PSU gRPC frame to child stdin");
            break;
        }

        if let Err(error) = stdin.flush().await {
            warn!(process_id, %error, "Failed to flush child stdin");
            break;
        }
    }

    let _ = stdin.shutdown().await;
    closed_from_end_of_stream
}

async fn pump_stderr_diagnostics<R>(
    stderr: R,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    agent_id: String,
    connection_id: String,
    process_id: i32,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stderr).lines();
    while let Some(line) = lines.next_line().await.context("failed to read child stderr")? {
        if line.trim().is_empty() {
            continue;
        }

        outgoing_tx
            .send(agent_message(
                &agent_id,
                &connection_id,
                AgentPayload::Diagnostic(diagnostic("warning", format!("pwsh[{process_id}] {line}"))),
            ))
            .await
            .context("failed to send PSU gRPC stderr diagnostic")?;
    }

    Ok(())
}

fn ends_with_line_ending(data: &[u8]) -> bool {
    data.ends_with(b"\n") || data.ends_with(b"\r")
}
