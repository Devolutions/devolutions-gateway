use anyhow::Context;
use tokio::io::AsyncWriteExt;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let mut arg = std::env::args();
    let input = arg
        .find(|arg| arg.starts_with("--input"))
        .context("input path is required")?;

    let input = input.split("=").last().context("file path is required")?;

    let output = arg
        .find(|arg| arg.starts_with("--output"))
        .context("output path is required")?;

    let output = output.split("=").last().context("output path is required")?;

    let file = tokio::fs::File::open(input).await?;
    let (_task, mut output_reader) = terminal_streamer::trp_decoder::decode_stream(file)?;
    let mut output_file = tokio::fs::File::create(output).await?;

    tokio::io::copy(&mut output_reader, &mut output_file).await?;
    output_file.flush().await?;

    Ok(())
}
