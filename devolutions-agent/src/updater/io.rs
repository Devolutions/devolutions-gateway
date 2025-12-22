//! IO utilities for the updater logic

use camino::{Utf8Path, Utf8PathBuf};
use futures::TryFutureExt;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::config::dto::ProxyConf;
use crate::updater::UpdaterError;

/// Parse file:// URL according to RFC 8089
///
/// Supports:
/// - file:///C:/path/to/file (Windows absolute path with drive letter)
/// - file://C:/path/to/file (Windows absolute path, lenient parsing)
/// - file:///path/to/file (Unix absolute path)
/// - file://path/to/file (relative path, lenient parsing)
pub(crate) fn parse_file_url(url: &str) -> Option<&Utf8Path> {
    let path = url.strip_prefix("file://")?;

    // RFC 8089: file:///C:/... (three slashes before drive letter)
    // Also accept file://C:/... (two slashes, lenient parsing)
    if let Some(rest) = path.strip_prefix('/') {
        Some(Utf8Path::new(rest))
    } else {
        // No leading slash after file:// - use path as-is
        Some(Utf8Path::new(path))
    }
}

/// Download binary file to memory.
pub(crate) async fn download_binary(url: &str, proxy_conf: &ProxyConf) -> Result<Vec<u8>, UpdaterError> {
    if let Some(path) = parse_file_url(url) {
        info!(%url, "Reading file from local filesystem...");
        tokio::fs::read(path).await.map_err(UpdaterError::Io)
    } else {
        info!(%url, "Downloading file from network...");

        let target_url = url::Url::parse(url)
            .map_err(|e| UpdaterError::Io(std::io::Error::other(format!("invalid url ({url}): {e}"))))?;

        let proxy_config = proxy_conf.to_proxy_config();

        let client =
            http_client_proxy::get_or_create_cached_client(reqwest::Client::builder(), &target_url, &proxy_config)
                .map_err(|source| UpdaterError::FileDownload {
                    source,
                    url: url.to_owned(),
                })?;

        let body = client
            .get(url)
            .send()
            .and_then(|response| response.bytes())
            .map_err(|source| UpdaterError::FileDownload {
                source,
                url: url.to_owned(),
            })
            .await?;

        Ok(body.to_vec())
    }
}

/// Download UTF-8 file to memory
pub(crate) async fn download_utf8(url: &str, proxy_conf: &ProxyConf) -> Result<String, UpdaterError> {
    let bytes = download_binary(url, proxy_conf).await?;
    String::from_utf8(bytes).map_err(|_| UpdaterError::Utf8)
}

/// Save data to a temporary file
pub(crate) async fn save_to_temp_file(data: &[u8], extension: Option<&str>) -> Result<Utf8PathBuf, UpdaterError> {
    let uuid = uuid::Uuid::new_v4();

    let file_name = match extension {
        Some(ext) => format!("{uuid}.{}", ext),
        None => uuid.to_string(),
    };

    let file_path = Utf8PathBuf::from_path_buf(std::env::temp_dir())
        .expect("BUG: OS Should always return valid UTF-8 temp path")
        .join(file_name);

    let mut file = File::create(&file_path).await?;
    file.write_all(data).await?;

    remove_file_on_reboot(&file_path)?;

    Ok(file_path)
}

/// Mark file to be removed on next reboot.
pub(crate) fn remove_file_on_reboot(file_path: &Utf8Path) -> Result<(), UpdaterError> {
    remove_file_on_reboot_impl(file_path)
}

#[cfg(windows)]
pub(crate) fn remove_file_on_reboot_impl(file_path: &Utf8Path) -> Result<(), UpdaterError> {
    use win_api_wrappers::utils::WideString;
    use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};

    let wide_file_path = WideString::from(file_path.as_str());

    // SAFETY: `wide_file_path` is a valid null-terminated UTF-16 string, therefore the function is
    // safe to call.
    let move_result = unsafe { MoveFileExW(wide_file_path.as_pcwstr(), None, MOVEFILE_DELAY_UNTIL_REBOOT) };

    if let Err(error) = move_result {
        warn!(%error, %file_path, "Failed to mark file for deletion on reboot");
    }

    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn impl_remove_file_on_reboot_impl(_file_path: &Utf8Path) -> Result<(), UpdaterError> {
    // NOTE: On UNIX-like platforms /tmp folder is used which is cleared by OS automatically.
    Ok(())
}
