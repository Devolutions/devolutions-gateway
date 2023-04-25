use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::token::{CurrentJrl, JrecTokenClaims, RecordingOperation, TokenCache, TokenError};

use anyhow::Context as _;
use camino::Utf8Path;
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, BufWriter};
use tokio::{fs, io};
use typed_builder::TypedBuilder;
use uuid::Uuid;

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
        if claims.jet_rop != RecordingOperation::Push {
            Err(AuthorizationError::Forbidden)
        } else {
            Ok(claims)
        }
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JrecManifest<'a> {
    session_id: Uuid,
    file_type: &'a str,
    start_time: i64,
    duration: i64,
}

impl JrecManifest<'_> {
    pub fn save_to_file(&self, path: &Utf8Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[derive(TypedBuilder)]
pub struct PlainForward<'a, S> {
    conf: Arc<Conf>,
    claims: JrecTokenClaims,
    client_stream: S,
    file_type: &'a str,
}

impl<S> PlainForward<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[instrument(skip_all)]
    pub async fn run(self) -> anyhow::Result<()> {
        let Self {
            conf,
            claims,
            mut client_stream,
            file_type,
        } = self;

        let session_id = claims.jet_aid;

        let recording_path = conf.recording_path.join(session_id.to_string());

        if recording_path.exists() {
            debug!(path = %recording_path, "Recording directory already exists");
        } else {
            trace!(path = %recording_path, "Create recording directory");
            fs::create_dir_all(&recording_path)
                .await
                .with_context(|| format!("Failed to create recording path: {recording_path}"))?;
        }

        // TODO: try to retrieve this information from the currently running session if applicable.
        let start_time = chrono::Utc::now().timestamp();

        let mut manifest = JrecManifest {
            session_id,
            file_type,
            start_time,
            duration: 0,
        };

        let path_base = recording_path.join("recording");

        let manifest_file = path_base.with_extension("json");
        manifest.save_to_file(&manifest_file)?;

        let recording_file = path_base.with_extension(file_type);

        debug!(path = %recording_file, "Opening file");

        let mut file = fs::OpenOptions::new()
            .read(false)
            .write(true)
            .create(true)
            .open(&recording_file)
            .await
            .with_context(|| format!("Failed to open file at {recording_file}"))
            .map(BufWriter::new)?;

        io::copy(&mut client_stream, &mut file)
            .await
            .context("JREC streaming to file")?;

        let end_time = chrono::Utc::now().timestamp();
        manifest.duration = end_time - start_time;
        manifest.save_to_file(&manifest_file)?;

        Ok(())
    }
}
