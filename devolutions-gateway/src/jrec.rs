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
                .with_context(|| format!("Failed to create recording path: {recording_path}"))?;
        }

        let session_id = claims.jet_aid;
        let file_ext = claims.jet_rft.as_str();
        let filename = format!("{session_id}.{file_ext}");

        let path = recording_path.join(filename);

        debug!(%path, "Opening file");

        let mut file = fs::OpenOptions::new()
            .read(false)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .with_context(|| format!("Failed to open file at {path}"))
            .map(BufWriter::new)?;

        debug!(%path, "File opened");

        io::copy(&mut client_stream, &mut file)
            .await
            .context("JREC streaming to file")?;

        Ok(())
    }
}
