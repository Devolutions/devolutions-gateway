use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::config::Conf;
use crate::token::{CurrentJrl, JrecTokenClaims, RecordingOperation, TokenCache, TokenError};

use anyhow::Context as _;
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecFile {
    file_name: String,
    start_time: i64,
    duration: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JrecManifest {
    session_id: Uuid,
    start_time: i64,
    duration: i64,
    files: Vec<JrecFile>,
}

impl JrecManifest {
    fn read_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let json = std::fs::read(path)?;
        let manifest = serde_json::from_slice(&json)?;
        Ok(manifest)
    }

    fn save_to_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[derive(TypedBuilder)]
pub struct ClientPush<'a, S> {
    conf: Arc<Conf>,
    claims: JrecTokenClaims,
    client_stream: S,
    file_type: &'a str,
    session_id: Uuid,
}

// FIXME: at some point, we should track ongoing recordings and make sure there is no data race to write the manifest file

impl<S> ClientPush<'_, S>
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
            session_id,
        } = self;

        if session_id != claims.jet_aid {
            anyhow::bail!("inconsistent session ID (ID in token: {})", claims.jet_aid);
        }

        let recording_path = conf.recording_path.join(session_id.to_string());
        let manifest_file = recording_path.join("recording.json");

        let (file_idx, mut manifest) = if recording_path.exists() {
            debug!(path = %recording_path, "Recording directory already exists");

            let mut existing_manifest =
                JrecManifest::read_from_file(&manifest_file).context("read manifest from disk")?;
            let next_file_idx = existing_manifest.files.len();

            let start_time = chrono::Utc::now().timestamp();

            existing_manifest.files.push(JrecFile {
                start_time,
                duration: 0,
                file_name: format!("recording-{next_file_idx}.{file_type}"),
            });

            existing_manifest
                .save_to_file(&manifest_file)
                .context("override existing manifest")?;

            (next_file_idx, existing_manifest)
        } else {
            debug!(path = %recording_path, "Create recording directory");

            fs::create_dir_all(&recording_path)
                .await
                .with_context(|| format!("Failed to create recording path: {recording_path}"))?;

            let start_time = chrono::Utc::now().timestamp();

            let first_file = JrecFile {
                start_time,
                duration: 0,
                file_name: format!("recording-0.{file_type}"),
            };

            let initial_manifest = JrecManifest {
                session_id,
                start_time,
                duration: 0,
                files: vec![first_file],
            };

            initial_manifest
                .save_to_file(&manifest_file)
                .context("write initial manifest to disk")?;

            (0, initial_manifest)
        };

        let current_file = manifest
            .files
            .get_mut(file_idx)
            .context("this is a bug: invalid file index")?;

        let recording_file = recording_path.join(&current_file.file_name);

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

        current_file.duration = end_time - current_file.start_time;
        manifest.duration = end_time - manifest.start_time;

        debug!(path = %manifest_file, "write updated manifest to disk");

        manifest
            .save_to_file(&manifest_file)
            .context("write updated manifest to disk")?;

        Ok(())
    }
}
