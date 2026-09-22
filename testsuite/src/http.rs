use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_SIZE: usize = 64 * 1024;

pub struct HttpRequestCapture {
    listener: TcpListener,
    url: String,
}

pub struct CapturedHttpRequest {
    headers: Vec<(String, String)>,
}

impl HttpRequestCapture {
    pub async fn bind() -> anyhow::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind HTTP request capture")?;
        let address = listener.local_addr().context("read HTTP request capture address")?;

        Ok(Self {
            listener,
            url: format!("http://{address}"),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn receive(self) -> anyhow::Result<CapturedHttpRequest> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.receive_inner())
            .await
            .context("timed out waiting for HTTP request")?
    }

    async fn receive_inner(self) -> anyhow::Result<CapturedHttpRequest> {
        let (mut stream, _) = self.listener.accept().await.context("accept HTTP request")?;
        let mut request = Vec::new();
        let mut buffer = [0; 1024];

        let header_end = loop {
            let read = stream.read(&mut buffer).await.context("read HTTP request headers")?;
            anyhow::ensure!(read != 0, "HTTP request ended before its headers");
            anyhow::ensure!(
                request.len() + read <= MAX_REQUEST_SIZE,
                "HTTP request exceeds {MAX_REQUEST_SIZE} bytes"
            );
            request.extend_from_slice(&buffer[..read]);

            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };

        let head = std::str::from_utf8(&request[..header_end]).context("HTTP request headers are not valid UTF-8")?;
        let mut lines = head.split("\r\n");
        anyhow::ensure!(
            lines.next().is_some_and(|line| !line.is_empty()),
            "HTTP request line is missing"
        );

        let mut headers = Vec::new();
        let mut content_length = 0;

        for line in lines.take_while(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').context("malformed HTTP request header")?;
            let value = value.trim();

            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().context("invalid HTTP request content length")?;
            }

            headers.push((name.to_owned(), value.to_owned()));
        }

        anyhow::ensure!(
            content_length <= MAX_REQUEST_SIZE - header_end,
            "HTTP request exceeds {MAX_REQUEST_SIZE} bytes"
        );

        let mut body_read = request.len() - header_end;
        while body_read < content_length {
            let remaining = content_length - body_read;
            let read_length = remaining.min(buffer.len());
            let read = stream
                .read(&mut buffer[..read_length])
                .await
                .context("read HTTP request body")?;
            anyhow::ensure!(read != 0, "HTTP request ended before its body");
            body_read += read;
        }

        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .context("write HTTP response")?;

        Ok(CapturedHttpRequest { headers })
    }
}

impl CapturedHttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(candidate, value)| candidate.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }
}
