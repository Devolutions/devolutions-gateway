use std::collections::HashMap;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::psu_grpc_agent::protocol::agent_message::Payload as AgentPayload;
use crate::psu_grpc_agent::protocol::{AgentMessage, ProcessCompleted, ProcessStarted, StartProcess, StreamData};
use crate::psu_grpc_agent::{agent_message, diagnostic, stream_closed, stream_data};

const PWSH_STDIN_CLOSED_EXIT_CODE: i32 = 160;

#[derive(Debug)]
pub(super) struct ProcessControl {
    pub(super) stop: mpsc::Sender<bool>,
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
            // Close the stream when it is the last frame, or when the receiver is
            // gone (send failed), so the mapping is never leaked in the registry.
            let send_failed = sender.send(stream_data).await.is_err();
            if end_of_stream || send_failed {
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
        let control = {
            let mut inner = self.inner.lock().await;
            if kill_process {
                inner.processes.remove(correlation_id).map(|control| control.stop)
            } else {
                inner.processes.get(correlation_id).map(|control| control.stop.clone())
            }
        };

        if let Some(control) = control {
            let _ = control.send(kill_process).await;
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
    control_rx: mpsc::Receiver<bool>,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    registry: ProcessRegistry,
    agent_id: String,
    connection_id: String,
    default_executable: String,
) -> anyhow::Result<()> {
    let correlation_id = request.correlation_id.clone();
    let stream_id = request.stream_id.clone();

    let result = run_process_inner(
        request,
        incoming_rx,
        control_rx,
        outgoing_tx,
        agent_id,
        connection_id,
        default_executable,
    )
    .await;

    registry.close_stream(&stream_id).await;
    registry.remove_process(&correlation_id).await;

    result
}

#[allow(clippy::too_many_arguments)]
async fn run_process_inner(
    request: StartProcess,
    incoming_rx: mpsc::Receiver<StreamData>,
    mut control_rx: mpsc::Receiver<bool>,
    outgoing_tx: mpsc::Sender<AgentMessage>,
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

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let error =
                anyhow::Error::new(error).context(format!("failed to start PSU gRPC child process using {executable}"));
            let error_message = format!("{error:#}");
            let _ = outgoing_tx
                .send(agent_message(
                    &agent_id,
                    &connection_id,
                    AgentPayload::StreamClosed(stream_closed(request.stream_id.clone(), error_message.clone(), true)),
                ))
                .await;
            let _ = send_process_completed(
                &outgoing_tx,
                &agent_id,
                &connection_id,
                &request.correlation_id,
                -1,
                false,
                error_message,
            )
            .await;
            return Err(error);
        }
    };
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
    let mut stdin_task = tokio::spawn(pump_server_to_stdin(incoming_rx, stdin, process_id));

    let mut stdin_closed_from_end_of_stream = false;
    let mut stdin_task_completed = false;
    let mut canceled = false;

    let status = loop {
        tokio::select! {
            status = child.wait() => break status.context("failed to wait for PSU gRPC child process")?,
            stdin_result = &mut stdin_task => {
                stdin_task_completed = true;
                stdin_closed_from_end_of_stream = stdin_result.unwrap_or(false);
                info!(process_id, "Finished receiving PSU gRPC stdin data; waiting for graceful child process exit");

                let (exit_status, killed) = wait_for_graceful_child_exit(&mut child, process_id).await?;
                canceled |= killed;
                break exit_status;
            }
            kill_process = control_rx.recv() => {
                match kill_process {
                    Some(true) => {
                        info!(process_id, correlation_id = %request.correlation_id, "Killing PSU gRPC child process on server request");
                        child.start_kill().context("failed to kill PSU gRPC child process")?;
                        canceled = true;
                        break child.wait().await.context("failed to wait for killed PSU gRPC child process")?;
                    }
                    Some(false) => {
                        info!(process_id, correlation_id = %request.correlation_id, "Gracefully stopping PSU gRPC child process by closing stdin");
                        canceled = true;
                        stdin_task.abort();
                        let _ = (&mut stdin_task).await;
                        stdin_task_completed = true;
                        let (exit_status, killed) = wait_for_graceful_child_exit(&mut child, process_id).await?;
                        canceled |= killed;
                        break exit_status;
                    }
                    None => {}
                }
            }
        }
    };

    if !stdin_task_completed {
        stdin_task.abort();
        let _ = stdin_task.await;
    }

    await_pump_task(stdout_task, process_id, "stdout").await;
    await_pump_task(stderr_task, process_id, "stderr").await;

    let exit_code = status.code().unwrap_or(-1);
    let expected_pwsh_exit = stdin_closed_from_end_of_stream && exit_code == PWSH_STDIN_CLOSED_EXIT_CODE;
    if expected_pwsh_exit {
        info!(
            process_id,
            exit_code, "PSU gRPC child process exited with expected code after stdin EOF for pwsh -s"
        );
    } else {
        info!(process_id, exit_code, "PSU gRPC child process exited");
    }

    // Reflect the actual outcome so the server can distinguish success from
    // cancellation or a non-zero exit based on the StreamClosed message.
    let stream_error = canceled || (exit_code != 0 && !expected_pwsh_exit);
    let stream_reason = if canceled {
        "child process canceled".to_owned()
    } else if stream_error {
        format!("child process exited with code {exit_code}")
    } else {
        "child process completed".to_owned()
    };

    let _ = outgoing_tx
        .send(agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::StreamClosed(stream_closed(
                request.stream_id.clone(),
                stream_reason,
                stream_error,
            )),
        ))
        .await;

    send_process_completed(
        &outgoing_tx,
        &agent_id,
        &connection_id,
        &request.correlation_id,
        exit_code,
        canceled,
        String::new(),
    )
    .await
    .context("failed to send PSU gRPC ProcessCompleted message")?;

    Ok(())
}

async fn wait_for_graceful_child_exit(child: &mut Child, process_id: i32) -> anyhow::Result<(ExitStatus, bool)> {
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => Ok((status.context("failed to wait for PSU gRPC child process")?, false)),
        Err(_) => {
            warn!(
                process_id,
                "PSU gRPC child process did not exit after stdin closed; killing child process"
            );
            child.start_kill().context("failed to kill PSU gRPC child process")?;
            let status = child
                .wait()
                .await
                .context("failed to wait for killed PSU gRPC child process")?;
            Ok((status, true))
        }
    }
}

async fn await_pump_task(mut task: JoinHandle<anyhow::Result<()>>, process_id: i32, stream_name: &'static str) {
    tokio::select! {
        result = &mut task => match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(process_id, stream_name, error = format!("{error:#}"), "PSU gRPC child stream pump failed"),
            Err(error) => warn!(process_id, stream_name, %error, "PSU gRPC child stream pump panicked"),
        },
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            warn!(process_id, stream_name, "Timed out draining PSU gRPC child stream pump");
            task.abort();
            let _ = task.await;
        }
    }
}

async fn send_process_completed(
    outgoing_tx: &mpsc::Sender<AgentMessage>,
    agent_id: &str,
    connection_id: &str,
    correlation_id: &str,
    exit_code: i32,
    canceled: bool,
    error_message: String,
) -> anyhow::Result<()> {
    outgoing_tx
        .send(agent_message(
            agent_id,
            connection_id,
            AgentPayload::ProcessCompleted(ProcessCompleted {
                correlation_id: correlation_id.to_owned(),
                exit_code,
                canceled,
                error_message,
            }),
        ))
        .await
        .context("failed to send PSU gRPC ProcessCompleted message")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn graceful_stop_keeps_process_registered_for_later_kill() {
        let registry = ProcessRegistry::default();
        let (control_tx, mut control_rx) = mpsc::channel(8);

        registry
            .register_process("correlation-id".to_owned(), ProcessControl { stop: control_tx })
            .await;

        registry.stop_process("correlation-id", false).await;
        assert_eq!(control_rx.recv().await, Some(false));
        assert!(registry.inner.lock().await.processes.contains_key("correlation-id"));

        registry.stop_process("correlation-id", true).await;
        assert_eq!(control_rx.recv().await, Some(true));
        assert!(!registry.inner.lock().await.processes.contains_key("correlation-id"));
    }

    #[tokio::test]
    async fn run_process_cleans_registry_and_reports_spawn_failure() {
        let registry = ProcessRegistry::default();
        let incoming_rx = registry.register_stream("stream-id").await;
        let (control_tx, control_rx) = mpsc::channel(8);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(8);

        registry
            .register_process("correlation-id".to_owned(), ProcessControl { stop: control_tx })
            .await;

        let result = run_process(
            StartProcess {
                correlation_id: "correlation-id".to_owned(),
                stream_id: "stream-id".to_owned(),
                executable: "definitely-not-a-devolutions-agent-test-command".to_owned(),
                arguments: Vec::new(),
                working_directory: String::new(),
                environment: HashMap::new(),
                metadata: HashMap::new(),
            },
            incoming_rx,
            control_rx,
            outgoing_tx,
            registry.clone(),
            "agent-id".to_owned(),
            "connection-id".to_owned(),
            "pwsh".to_owned(),
        )
        .await;

        assert!(result.is_err());

        let registry = registry.inner.lock().await;
        assert!(registry.streams.is_empty());
        assert!(registry.processes.is_empty());
        drop(registry);

        let stream_message = outgoing_rx.recv().await.expect("stream closed message");
        match stream_message.payload {
            Some(AgentPayload::StreamClosed(closed)) => {
                assert_eq!(closed.stream_id, "stream-id");
                assert!(closed.error);
                assert!(closed.reason.contains("failed to start PSU gRPC child process"));
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }

        let completed_message = outgoing_rx.recv().await.expect("process completed message");
        match completed_message.payload {
            Some(AgentPayload::ProcessCompleted(completed)) => {
                assert_eq!(completed.correlation_id, "correlation-id");
                assert_eq!(completed.exit_code, -1);
                assert!(!completed.canceled);
                assert!(
                    completed
                        .error_message
                        .contains("failed to start PSU gRPC child process")
                );
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
    }
}
