//! A SOCKS proxy for the channel tests: SOCKS5 (RFC 1928, with RFC 1929 user/password authentication), and SOCKS4
//! with its 4A extension for names.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// One `CONNECT` request the proxy received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SocksRequest {
    /// The user name and password of a user/password authentication.
    pub(super) credentials: Option<(String, String)>,
    /// The destination name, when the client left resolution to the proxy; `None` for an address.
    pub(super) domain: Option<String>,
}

/// A SOCKS proxy listening on loopback that connects every request to its port on `127.0.0.1`.
pub(super) struct TestSocksProxy {
    /// The `host:port` the proxy listens on.
    pub(super) host: String,
    requests: Arc<Mutex<Vec<SocksRequest>>>,
    task: JoinHandle<()>,
}

impl TestSocksProxy {
    pub(super) async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let host = listener.local_addr()?.to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let _ = serve(client, &recorded).await;
                });
            }
        });
        Ok(Self { host, requests, task })
    }

    pub(super) fn requests(&self) -> Vec<SocksRequest> {
        self.requests.lock().expect("SOCKS requests lock").clone()
    }
}

impl Drop for TestSocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

const VERSION: u8 = 5;
const SOCKS4_VERSION: u8 = 4;
const CONNECT: u8 = 1;
const SOCKS4_GRANTED: u8 = 90;
const NO_AUTHENTICATION: u8 = 0x00;
const USER_PASSWORD: u8 = 0x02;
const IPV4: u8 = 0x01;
const DOMAIN: u8 = 0x03;
const IPV6: u8 = 0x04;

async fn serve(mut client: TcpStream, requests: &Mutex<Vec<SocksRequest>>) -> anyhow::Result<()> {
    match client.read_u8().await? {
        VERSION => {}
        SOCKS4_VERSION => return serve_socks4(client, requests).await,
        version => anyhow::bail!("unknown SOCKS version {version}"),
    }
    let mut methods = vec![0; usize::from(client.read_u8().await?)];
    client.read_exact(&mut methods).await?;
    let credentials = if methods.contains(&USER_PASSWORD) {
        client.write_all(&[VERSION, USER_PASSWORD]).await?;
        anyhow::ensure!(client.read_u8().await? == 1, "unknown authentication version");
        let user = read_length_prefixed(&mut client).await?;
        let password = read_length_prefixed(&mut client).await?;
        client.write_all(&[1, 0x00]).await?;
        Some((user, password))
    } else {
        anyhow::ensure!(methods.contains(&NO_AUTHENTICATION), "no supported method");
        client.write_all(&[VERSION, NO_AUTHENTICATION]).await?;
        None
    };
    let mut header = [0; 4];
    client.read_exact(&mut header).await?;
    anyhow::ensure!(header[..2] == [VERSION, CONNECT], "not a CONNECT request");
    let domain = match header[3] {
        IPV4 => {
            client.read_exact(&mut [0; 4]).await?;
            None
        }
        DOMAIN => Some(read_length_prefixed(&mut client).await?),
        IPV6 => {
            client.read_exact(&mut [0; 16]).await?;
            None
        }
        address_type => anyhow::bail!("unknown address type {address_type}"),
    };
    let port = client.read_u16().await?;
    requests
        .lock()
        .expect("SOCKS requests lock")
        .push(SocksRequest { credentials, domain });
    let mut upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    client.write_all(&[VERSION, 0x00, 0x00, IPV4, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn read_length_prefixed(client: &mut TcpStream) -> anyhow::Result<String> {
    let mut bytes = vec![0; usize::from(client.read_u8().await?)];
    client.read_exact(&mut bytes).await?;
    Ok(String::from_utf8(bytes)?)
}

/// Serves a SOCKS4 `CONNECT` whose version byte `serve` has read; an address `0.0.0.x` with a nonzero `x` announces a
/// SOCKS4A name after the user ID.
async fn serve_socks4(mut client: TcpStream, requests: &Mutex<Vec<SocksRequest>>) -> anyhow::Result<()> {
    anyhow::ensure!(client.read_u8().await? == CONNECT, "not a CONNECT request");
    let port = client.read_u16().await?;
    let mut address = [0; 4];
    client.read_exact(&mut address).await?;
    let user = read_null_terminated(&mut client).await?;
    let domain = match address {
        [0, 0, 0, last] if last != 0 => Some(read_null_terminated(&mut client).await?),
        _ => None,
    };
    let credentials = (!user.is_empty()).then(|| (user, String::new()));
    requests
        .lock()
        .expect("SOCKS requests lock")
        .push(SocksRequest { credentials, domain });
    let mut upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    client.write_all(&[0, SOCKS4_GRANTED, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn read_null_terminated(client: &mut TcpStream) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    loop {
        match client.read_u8().await? {
            0 => return Ok(String::from_utf8(bytes)?),
            byte => bytes.push(byte),
        }
    }
}
