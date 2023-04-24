use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::token::{CurrentJrl, JrecTokenClaims, TokenCache, TokenError};

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
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
        Ok(claims)
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct JrecManifest {
    session_id: Uuid,
    file_type: String,
    start_time: i64,
    duration: i64,
}

impl JrecManifest {
    pub fn save_to_file(&self, path: &Utf8Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json)?;
        Ok(())
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

        let session_id = claims.jet_aid;
        let session_id_str = session_id.hyphenated().to_string();

        let mut recording_path = conf.recording_path.clone();
        recording_path.push(session_id_str.as_str());

        if !recording_path.exists() {
            fs::create_dir_all(&recording_path)
                .await
                .with_context(|| format!("Failed to create recording path: {recording_path}"))?;
        }

        let start_time = chrono::Utc::now().timestamp();
        let file_type = claims.jet_rft.as_str();

        let mut manifest = JrecManifest {
            session_id: session_id.clone(),
            file_type: file_type.to_string(),
            start_time: start_time,
            duration: 0,
        };

        let manifest_file = recording_path.join("session.json");
        manifest.save_to_file(&manifest_file)?;

        let filename = format!("session.{0}", file_type);
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

        io::copy(&mut client_stream, &mut file)
            .await
            .context("JREC streaming to file")?;

        let end_time = chrono::Utc::now().timestamp();
        manifest.duration = end_time - start_time;
        manifest.save_to_file(&manifest_file)?;

        Ok(())
    }
}
