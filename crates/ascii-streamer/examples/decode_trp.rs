use tokio::io::AsyncWriteExt;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let mut arg = std::env::args();
    let input = arg
        .find(|arg| arg.starts_with("--input"))
        .ok_or(anyhow::anyhow!("input path is required"))?;

    let input = input
        .split("=")
        .last()
        .ok_or(anyhow::anyhow!("file path is required"))?;

    let output = arg
        .find(|arg| arg.starts_with("--output"))
        .ok_or(anyhow::anyhow!("output path is required"))?;

    let output = output
        .split("=")
        .last()
        .ok_or(anyhow::anyhow!("output path is required"))?;

    let file = tokio::fs::File::open(input).await?;
    let mut output_reader = ascii_streamer::trp_decoder::decode_buffer(file)?;
    let mut output_file = tokio::fs::File::create(output).await?;

    tokio::io::copy(&mut output_reader, &mut output_file).await?;
    output_file.flush().await?;

    Ok(())
}
