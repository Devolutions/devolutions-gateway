use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::token::{CurrentJrl, JrecTokenClaims, TokenCache, TokenError};

use anyhow::Context as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, BufWriter};
use tokio::{fs, io};
use typed_builder::TypedBuilder;

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("token not allowed")]
    Forbidden,
    #[error("bad token")]
    BadToken(#[from] TokenError),
}

pub fn authorize(
    client_addr: SocketAddr,
    token: &str,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> Result<JrecTokenClaims, AuthorizationError> {
    use crate::token::AccessTokenClaims;

    if let AccessTokenClaims::Jrec(claims) =
        crate::http::middlewares::auth::authenticate(client_addr, token, conf, token_cache, jrl)?
    {
        Ok(claims)
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

#[derive(TypedBuilder)]
pub struct PlainForward<S> {
    conf: Arc<Conf>,
    claims: JrecTokenClaims,
    client_stream: S,
}

impl<S> PlainForward<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[instrument(skip_all)]
    pub async fn run(self) -> anyhow::Result<()> {
        let Self {
            conf,
            claims,
            mut client_stream,
        } = self;

        let recording_path = &conf.recording_path.clone();

        if !recording_path.exists() {
            fs::create_dir_all(recording_path)
                .await
                .with_context(|| format!("Failed to create recording path: {}", recording_path))?;
        }

        let file_ext: &str = claims.jet_rft.into();
        let filename = format!("{}.{}", claims.jet_aid, file_ext);
        let path = recording_path.join(filename);

        info!(%path, "Opening file");

        let file = fs::OpenOptions::new()
            .read(false)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .with_context(|| format!("Failed to open file at {}", path))?;

        info!(%path, "File opened");

        let mut file_writer = BufWriter::new(file);

        io::copy(&mut client_stream, &mut file_writer)
            .await
            .context("JREC WebSocket to file proxying")?;

        Ok(())
    }
}
