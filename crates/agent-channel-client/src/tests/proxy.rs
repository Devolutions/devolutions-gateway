//! An HTTP CONNECT proxy for the channel tests.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// A proxy listening on loopback that tunnels every `CONNECT` and records its request head.
pub(super) struct TestProxy {
    /// The `host:port` the proxy listens on.
    pub(super) host: String,
    heads: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl TestProxy {
    /// Starts a proxy; with `tls`, clients reach it over TLS, as an `https://` proxy.
    pub(super) async fn start(tls: Option<rustls::ServerConfig>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let host = listener.local_addr()?.to_string();
        let acceptor = tls.map(|config| TlsAcceptor::from(Arc::new(config)));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&heads);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(tls) = acceptor.accept(tcp).await {
                                tunnel(tls, &recorded).await;
                            }
                        }
                        None => tunnel(tcp, &recorded).await,
                    }
                });
            }
        });
        Ok(Self { host, heads, task })
    }

    /// The request heads of the tunnels clients asked for.
    pub(super) fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("proxy heads lock").clone()
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn tunnel<S>(mut client: S, heads: &Mutex<Vec<String>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut chunk = [0; 1024];
    while !head.ends_with(b"\r\n\r\n") {
        match client.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    heads.lock().expect("proxy heads lock").push(head.clone());
    let Some(target) = head
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_once(' '))
        .map(|(target, _)| target.to_owned())
    else {
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_ok()
    {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }
}
