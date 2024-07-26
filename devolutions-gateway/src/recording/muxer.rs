use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;

pub async fn remux(input: impl AsRef<Path>) -> anyhow::Result<()> {
    let path = Arc::new(input.as_ref().to_owned());
    // Could potentially be a very slow operation
    tokio::task::spawn_blocking(|| remux_impl(path)).await??;
    Ok(())
}

fn remux_impl(input: Arc<PathBuf>) -> anyhow::Result<()> {
    std::thread::sleep(Duration::from_secs(1));
    let input_to_remux = input.as_ref();
    let output = input_to_remux
        .as_path()
        .ancestors()
        .nth(1)
        .with_context(|| "failed to create muxer cache file")?
        .join(format!(
            "muxer_cache_{}",
            input_to_remux
                .file_name()
                .ok_or(anyhow::anyhow!("input file has no file name"))?
                .to_string_lossy()
        ));
    cadeau::xmf::muxer::webm_remux(input_to_remux, output.as_path()).with_context(|| {
        format!(
            "failed to remux file: {}, output: {}",
            input_to_remux.display(),
            output.display(),
        )
    })?;

    std::fs::copy(output.as_path(), input_to_remux).with_context(|| "failed to copy remuxed file")?;
    std::fs::remove_file(output).with_context(|| "failed to remove temporary file")?;
    debug!(?input_to_remux, "Successfully Remuxed file");
    Ok(())
}
