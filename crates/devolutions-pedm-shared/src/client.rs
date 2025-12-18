use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use devolutions_pedm_client_http::apis::client::APIClient;
pub use devolutions_pedm_client_http::models;
use hyper::Uri;
use hyper::body::HttpBody;
use hyper::client::connect::{Connected, Connection};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tower::Service;
use win_api_wrappers::raw::Win32::Foundation::ERROR_PIPE_BUSY;
use win_api_wrappers::raw::Win32::Storage::FileSystem::SECURITY_IMPERSONATION;

#[pin_project]
struct NamedPipeStream(#[pin] NamedPipeClient);

unsafe impl Sync for NamedPipeStream {}
unsafe impl Send for NamedPipeStream {}

impl AsyncRead for NamedPipeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl AsyncWrite for NamedPipeStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().0.poll_shutdown(cx)
    }
}

impl Connection for NamedPipeStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[derive(Clone)]
struct NamedPipeConnector;

impl Service<Uri> for NamedPipeConnector {
    type Response = NamedPipeStream;
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Uri) -> Self::Future {
        Box::pin(async move {
            let mut iter = 0;
            loop {
                let client = ClientOptions::new()
                    .security_qos_flags(SECURITY_IMPERSONATION.0)
                    .open(r"\\.\pipe\DevolutionsPEDM");

                if iter < 5
                    && client
                        .as_ref()
                        .is_err_and(|e| e.raw_os_error() == Some(ERROR_PIPE_BUSY.to_hresult().0))
                {
                    iter += 1;

                    thread::sleep(Duration::from_millis(50));
                    continue;
                }

                break Ok(NamedPipeStream(client?));
            }
        })
    }
}

pub fn client() -> APIClient {
    APIClient::new(devolutions_pedm_client_http::apis::configuration::Configuration::new(
        hyper::Client::builder().build::<_, hyper::Body>(NamedPipeConnector),
    ))
}

pub async fn conv_resp(resp: devolutions_pedm_client_http::apis::Error) -> Result<models::ErrorResponse> {
    match resp {
        devolutions_pedm_client_http::apis::Error::Api(api_err) => Ok(serde_json::from_slice::<models::ErrorResponse>(
            &api_err.body.collect().await?.to_bytes(),
        )?),
        devolutions_pedm_client_http::apis::Error::Header(x) => bail!(x),
        devolutions_pedm_client_http::apis::Error::Http(x) => bail!(x),
        devolutions_pedm_client_http::apis::Error::Hyper(x) => bail!(x),
        devolutions_pedm_client_http::apis::Error::Serde(x) => bail!(x),
        devolutions_pedm_client_http::apis::Error::UriError(x) => bail!(x),
    }
}

pub fn block_req<F, R>(f: F) -> Result<Result<R, models::ErrorResponse>>
where
    F: Future<Output = Result<R, devolutions_pedm_client_http::apis::Error>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            Ok(match f.await {
                Ok(x) => Ok(x),
                Err(x) => Err(conv_resp(x).await?),
            })
        })
}
