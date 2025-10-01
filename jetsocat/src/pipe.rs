use crate::proxy::ProxyConfig;
use anyhow::{Context as _, Result};
use std::any::Any;
use std::path::PathBuf;
use transport::ErasedReadWrite;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum PipeMode {
    Stdio,
    ProcessCmd {
        command: String,
    },
    WriteFile {
        path: PathBuf,
    },
    ReadFile {
        path: PathBuf,
    },
    TcpListen {
        bind_addr: String,
    },
    Tcp {
        addr: String,
    },
    JetTcpAccept {
        addr: String,
        association_id: Uuid,
        candidate_id: Uuid,
    },
    JetTcpConnect {
        addr: String,
        association_id: Uuid,
        candidate_id: Uuid,
    },
    WebSocket {
        url: String,
    },
    WebSocketListen {
        bind_addr: String,
    },
    #[cfg(windows)]
    NamedPipe {
        name: String,
    },
    #[cfg(windows)]
    NamedPipeListen {
        name: String,
    },
    #[cfg(unix)]
    UnixSocket {
        path: PathBuf,
    },
    #[cfg(unix)]
    UnixSocketListen {
        path: PathBuf,
    },
}

pub struct Pipe {
    pub name: &'static str,
    pub stream: ErasedReadWrite,

    // Useful when we don't want to drop something before the Pipe
    _handle: Option<Box<dyn Any + Send>>,
}

pub async fn open_pipe(mode: PipeMode, proxy_cfg: Option<ProxyConfig>) -> Result<Pipe> {
    use anyhow::Context as _;
    use std::process::Stdio;
    use tokio::fs;
    use tokio::process::Command;

    match mode {
        PipeMode::Stdio => Ok(Pipe {
            name: "stdio",
            stream: Box::new(tokio::io::join(tokio::io::stdin(), tokio::io::stdout())),
            _handle: None,
        }),
        PipeMode::ProcessCmd { command } => {
            info!(%command, "Spawn subprocess");

            #[cfg(target_os = "windows")]
            let mut cmd = Command::new("cmd");
            #[cfg(target_os = "windows")]
            cmd.arg("/C");

            #[cfg(not(target_os = "windows"))]
            let mut cmd = Command::new("sh");
            #[cfg(not(target_os = "windows"))]
            cmd.arg("-c");

            let mut handle = cmd
                .arg(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .with_context(|| format!("spawn with command: {cmd:?}"))?;

            let stdout = handle.stdout.take().expect("spawned above");
            let stdin = handle.stdin.take().expect("spawned above");

            Ok(Pipe {
                name: "process",
                stream: Box::new(tokio::io::join(stdout, stdin)),
                _handle: Some(Box::new(handle)), // we need to store the handle because of kill_on_drop(true)
            })
        }
        PipeMode::WriteFile { path } => {
            info!(path = %path.display(), "Opening file");

            let file = fs::OpenOptions::new()
                .read(false)
                .write(true)
                .append(true)
                .create(true)
                .open(&path)
                .await
                .with_context(|| format!("open file at {}", path.display()))?;

            info!(path = %path.display(), "File opened");

            return Ok(Pipe {
                name: "write-file",
                stream: Box::new(WriteFile(file)),
                _handle: None,
            });

            struct WriteFile(fs::File);

            impl tokio::io::AsyncRead for WriteFile {
                fn poll_read(
                    self: std::pin::Pin<&mut Self>,
                    _: &mut std::task::Context<'_>,
                    _: &mut tokio::io::ReadBuf<'_>,
                ) -> std::task::Poll<std::io::Result<()>> {
                    std::task::Poll::Ready(Ok(()))
                }
            }

            impl tokio::io::AsyncWrite for WriteFile {
                fn poll_write(
                    self: std::pin::Pin<&mut Self>,
                    cx: &mut std::task::Context<'_>,
                    buf: &[u8],
                ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
                    std::pin::pin!(&mut self.get_mut().0).poll_write(cx, buf)
                }

                fn poll_flush(
                    self: std::pin::Pin<&mut Self>,
                    cx: &mut std::task::Context<'_>,
                ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
                    std::pin::pin!(&mut self.get_mut().0).poll_flush(cx)
                }

                fn poll_shutdown(
                    self: std::pin::Pin<&mut Self>,
                    cx: &mut std::task::Context<'_>,
                ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
                    std::pin::pin!(&mut self.get_mut().0).poll_shutdown(cx)
                }
            }
        }
        PipeMode::ReadFile { path } => {
            info!(path = %path.display(), "Opening file");

            let file = fs::OpenOptions::new()
                .read(true)
                .write(false)
                .create(false)
                .open(&path)
                .await
                .with_context(|| format!("open file at {}", path.display()))?;

            info!(path = %path.display(), "File opened");

            Ok(Pipe {
                name: "read-file",
                stream: Box::new(file),
                _handle: None,
            })
        }
        PipeMode::TcpListen { bind_addr } => {
            use tokio::net::TcpListener;

            info!(%bind_addr, "Listening for TCP");

            let listener = TcpListener::bind(bind_addr)
                .await
                .context("failed to bind TCP listener")?;
            let (socket, peer_addr) = listener.accept().await.context("TCP listener couldn't accept")?;

            info!(%peer_addr, "Accepted peer");

            Ok(Pipe {
                name: "tcp-listener",
                stream: Box::new(socket),
                _handle: None,
            })
        }
        PipeMode::Tcp { addr } => {
            use crate::utils::tcp_connect;

            info!(%addr, "TCP connect");

            let stream = tcp_connect(addr, proxy_cfg)
                .await
                .with_context(|| "TCP connect failed")?;

            debug!("Connected");

            Ok(Pipe {
                name: "tcp",
                stream,
                _handle: None,
            })
        }
        PipeMode::JetTcpAccept {
            addr,
            association_id,
            candidate_id,
        } => {
            use crate::jet::{read_jet_accept_response, write_jet_accept_request};
            use crate::utils::tcp_connect;

            info!(
                %addr, %association_id, %candidate_id,
                "TCP connect with JET accept protocol for {}/{}",
                association_id, candidate_id
            );

            let mut stream = tcp_connect(addr, proxy_cfg)
                .await
                .with_context(|| "TCP connect failed")?;

            debug!("Sending JET accept request…");
            write_jet_accept_request(&mut stream, association_id, candidate_id).await?;
            debug!("JET accept request sent, waiting for response…");
            read_jet_accept_response(&mut stream).await?;
            debug!("JET accept response received and processed successfully!");

            debug!("Connected");

            Ok(Pipe {
                name: "jet-tcp-accept",
                stream,
                _handle: None,
            })
        }
        PipeMode::JetTcpConnect {
            addr,
            association_id,
            candidate_id,
        } => {
            use crate::jet::{read_jet_connect_response, write_jet_connect_request};
            use crate::utils::tcp_connect;

            info!(
                %addr, %association_id, %candidate_id,
                "TCP connect with JET connect protocol for {}/{}", association_id, candidate_id
            );

            let mut stream = tcp_connect(addr, proxy_cfg)
                .await
                .with_context(|| "TCP connect failed")?;

            debug!("Sending JET connect request…");
            write_jet_connect_request(&mut stream, association_id, candidate_id).await?;
            debug!("JET connect request sent, waiting for response…");
            read_jet_connect_response(&mut stream).await?;
            debug!("JET connect response received and processed successfully!");

            debug!("Connected");

            Ok(Pipe {
                name: "jet-tcp-connect",
                stream,
                _handle: None,
            })
        }
        PipeMode::WebSocket { url } => {
            use crate::utils::ws_connect;

            info!(
                "Connecting WebSocket at {}",
                // Do not log the query part at info level
                if let Some((without_query, _)) = url.split_once('?') {
                    without_query
                } else {
                    &url
                }
            );

            let (stream, rsp) = ws_connect(url, proxy_cfg)
                .await
                .with_context(|| "WebSocket connect failed")?;

            debug!(?rsp, "Connected");

            Ok(Pipe {
                name: "websocket",
                stream,
                _handle: None,
            })
        }
        PipeMode::WebSocketListen { bind_addr } => {
            use crate::utils::websocket_handle;
            use tokio::net::TcpListener;
            use tokio_tungstenite::accept_async;

            info!(%bind_addr, "Listening for WebSocket");

            let listener = TcpListener::bind(bind_addr)
                .await
                .with_context(|| "Failed to bind TCP listener")?;
            let (socket, peer_addr) = listener
                .accept()
                .await
                .with_context(|| "TCP listener couldn't accept")?;

            info!(%peer_addr, "Accepted peer");

            let ws = accept_async(socket)
                .await
                .with_context(|| "WebSocket handshake failed")?;

            let stream = Box::new(websocket_handle(ws)) as ErasedReadWrite;

            Ok(Pipe {
                name: "websocket-listener",
                stream,
                _handle: None,
            })
        }
        #[cfg(windows)]
        PipeMode::NamedPipe { name } => {
            use std::time::Duration;
            use tokio::net::windows::named_pipe::ClientOptions;
            use tokio::time;

            const ERROR_PIPE_BUSY: i32 = 231;

            info!(%name, "Open named pipe...");

            let named_pipe = loop {
                match ClientOptions::new().open(&name) {
                    Ok(named_pipe) => break named_pipe,
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => (),
                    Err(e) => return Err(anyhow::Error::new(e).context("named pipe open")),
                }

                time::sleep(Duration::from_millis(50)).await;
            };

            debug!("Connected");

            Ok(Pipe {
                name: "named-pipe",
                stream: Box::new(named_pipe),
                _handle: None,
            })
        }
        #[cfg(windows)]
        PipeMode::NamedPipeListen { name } => {
            use tokio::net::windows::named_pipe::ServerOptions;

            info!(%name, "Create named pipe...");

            let named_pipe = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)
                .context("create named pipe")?;

            info!(%name, "Wait for a client to connect");

            named_pipe.connect().await.context("named pipe connect")?;

            info!("Peer connected");

            Ok(Pipe {
                name: "named-pipe-listener",
                stream: Box::new(named_pipe),
                _handle: None,
            })
        }
        #[cfg(unix)]
        PipeMode::UnixSocket { path } => {
            use tokio::net::UnixStream;

            info!(path = %path.display(), "UNIX socket connect");

            let stream = UnixStream::connect(path)
                .await
                .with_context(|| "UNIX socket connect failed")?;

            debug!("Connected");

            Ok(Pipe {
                name: "unix-socket",
                stream: Box::new(stream),
                _handle: None,
            })
        }
        #[cfg(unix)]
        PipeMode::UnixSocketListen { path } => {
            use tokio::net::UnixListener;

            info!(path = %path.display(), "Listening on UNIX socket");

            let listener = UnixListener::bind(&path).context("failed to bind UNIX listener")?;
            let handle = Box::new(UnlinkSocketOnDrop(path));

            let (socket, peer_addr) = listener.accept().await.context("UNIX listener couldn't accept")?;

            info!(?peer_addr, "Accepted peer");

            return Ok(Pipe {
                name: "unix-socket-listener",
                stream: Box::new(socket),
                _handle: Some(handle),
            });

            struct UnlinkSocketOnDrop(PathBuf);

            impl Drop for UnlinkSocketOnDrop {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(&self.0);
                }
            }
        }
    }
}

#[instrument(skip_all)]
pub async fn pipe(mut a: Pipe, mut b: Pipe) -> Result<()> {
    use tokio::io::{AsyncWriteExt as _, copy_bidirectional_with_sizes};

    const BUF_SIZE: usize = 16 * 1024;

    let forward = copy_bidirectional_with_sizes(&mut a.stream, &mut b.stream, BUF_SIZE, BUF_SIZE);

    info!(%a.name, %b.name, "Start piping");

    let result = forward
        .await
        .map(|_| ())
        .context("copy_bidirectional_with_sizes failed");

    info!("Ended");

    a.stream.shutdown().await?;
    b.stream.shutdown().await?;

    result
}
