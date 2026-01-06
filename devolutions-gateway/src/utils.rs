use std::fmt;
use std::net::SocketAddr;

use anyhow::Context as _;
use tokio::net::{TcpStream, lookup_host};
use url::Url;

use crate::target_addr::TargetAddr;

pub async fn tcp_connect(dest: &TargetAddr) -> anyhow::Result<(TcpStream, SocketAddr)> {
    const CONNECTION_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);

    let fut = async move {
        let addrs = lookup_host(dest.as_addr())
            .await
            .context("failed to lookup destination address")?;

        let mut last_err = None;

        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok((stream, addr)),
                Err(error) => {
                    warn!(%error, resolved = %addr, destination = %dest, "Failed to connect to a resolved address");
                    last_err = Some(anyhow::Error::new(error).context("TcpStream::connect"))
                }
            }
        }

        Err::<_, anyhow::Error>(last_err.unwrap_or_else(|| anyhow::format_err!("could not resolve to any address")))
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
    Fut: Future<Output = anyhow::Result<Out>>,
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

    (host, port).to_socket_addrs()?.next().context("no address resolved")
}

pub fn wildcard_host_match(wildcard_host: &str, actual_host: &str) -> bool {
    let mut expected_it = wildcard_host.rsplit('.');
    let mut actual_it = actual_host.rsplit('.');
    loop {
        match (expected_it.next(), actual_it.next()) {
            (Some(expected), Some(actual)) if expected.eq_ignore_ascii_case(actual) => {}
            (Some("*"), Some(_)) => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}
