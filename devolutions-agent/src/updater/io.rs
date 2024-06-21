//! IO utilities for the updater logic

use camino::Utf8Path;
use camino::Utf8PathBuf;
use futures::TryFutureExt;
use tokio::{fs::File, io::AsyncWriteExt};

use crate::updater::UpdaterError;

/// Download binary file to memory
pub async fn download_binary(url: &str) -> Result<Vec<u8>, UpdaterError> {
    info!(%url, "Downloading file from network...");

    let body = reqwest::get(url)
        .and_then(|response| response.bytes())
        .map_err(|source| UpdaterError::FileDownload {
            source,
            file_path: url.to_string(),
        })
        .await?;
    Ok(body.to_vec())
}

/// Download UTF-8 file to memory
pub async fn download_utf8(url: &str) -> Result<String, UpdaterError> {
    let bytes = download_binary(url).await?;
    String::from_utf8(bytes).map_err(|_| UpdaterError::Utf8)
}

/// Save data to a temporary file
pub async fn save_to_temp_file(data: &[u8], extension: Option<&str>) -> Result<Utf8PathBuf, UpdaterError> {
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
pub fn remove_file_on_reboot(file_path: &Utf8Path) -> Result<(), UpdaterError> {
    remove_file_on_reboot_impl(file_path)
}

#[cfg(windows)]
pub fn remove_file_on_reboot_impl(file_path: &Utf8Path) -> Result<(), UpdaterError> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

    let hstring_file_path = HSTRING::from(file_path.as_str());

    let move_result = unsafe { MoveFileExW(&hstring_file_path, None, MOVEFILE_DELAY_UNTIL_REBOOT) };

    if let Err(err) = move_result {
        warn!(%err, %file_path, "Failed to mark file for deletion on reboot");
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn impl_remove_file_on_reboot_impl(_file_path: &Utf8Path) -> Result<(), UpdaterError> {
    // NOTE: On UNIX-like platforms /tmp folder is used which is cleared by OS automatically.
    Ok(())
}
