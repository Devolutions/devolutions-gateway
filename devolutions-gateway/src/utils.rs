use anyhow::Context as _;
use std::fmt;
use std::net::SocketAddr;
use tokio::net::{lookup_host, TcpStream};
use url::Url;

use crate::target_addr::TargetAddr;

pub mod danger_transport {
    use tokio_rustls::rustls;

    pub struct NoCertificateVerification;

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

pub async fn resolve_target_addr(dest: &TargetAddr) -> anyhow::Result<SocketAddr> {
    let port = dest.port();

    if let Some(ip) = dest.host_ip() {
        Ok(SocketAddr::new(ip, port))
    } else {
        lookup_host((dest.host(), port))
            .await?
            .next()
            .context("host lookup yielded no result")
    }
}

pub async fn tcp_connect(dest: &TargetAddr) -> anyhow::Result<(TcpStream, SocketAddr)> {
    const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);

    let fut = async move {
        let socket_addr = resolve_target_addr(dest).await?;
        let stream = TcpStream::connect(socket_addr)
            .await
            .context("couldn't connect stream")?;
        Ok::<_, anyhow::Error>((stream, socket_addr))
    };
    let result = tokio::time::timeout(CONNECTION_TIMEOUT, fut).await??;
    Ok(result)
}

pub async fn successive_try<'a, F, Fut, In, Out>(
    inputs: impl IntoIterator<Item = &'a In>,
    func: F,
) -> anyhow::Result<(Out, &'a In)>
where
    In: fmt::Display + 'a,
    F: Fn(&'a In) -> Fut + 'a,
    Fut: core::future::Future<Output = anyhow::Result<Out>>,
{
    let mut error: Option<anyhow::Error> = None;

    for input in inputs {
        match func(input).await {
            Ok(o) => return Ok((o, input)),
            Err(e) => {
                let e = e.context(format!("{input} failed"));
                match error.take() {
                    Some(prev_err) => error = Some(prev_err.context(e)),
                    None => error = Some(e),
                }
            }
        }
    }

    Err(error.context("empty input list")?)
}

pub fn url_to_socket_addr(url: &Url) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;

    let host = url.host_str().context("bad url: host missing")?;
    let port = url.port_or_known_default().context("bad url: port missing")?;

    Ok((host, port).to_socket_addrs().unwrap().next().unwrap())
}
