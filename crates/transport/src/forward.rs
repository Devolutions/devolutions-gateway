use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct ForwardResult<R, W> {
    pub reader: R,
    pub writer: W,
    pub transferred_bytes: u64,
}

pub async fn forward<R, W>(mut reader: R, mut writer: W) -> Result<ForwardResult<R, W>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let transferred_bytes = tokio::io::copy(&mut reader, &mut writer)
        .await
        .context("copy operation")?;

    Ok(ForwardResult {
        reader,
        writer,
        transferred_bytes,
    })
}

pub struct BidirectionalForwardResult {
    pub nb_a_to_b: u64,
    pub nb_b_to_a: u64,
}

pub async fn forward_bidirectional<A, B>(mut a: A, mut b: B) -> Result<BidirectionalForwardResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (nb_a_to_b, nb_b_to_a) = tokio::io::copy_bidirectional(&mut a, &mut b)
        .await
        .context("copy_bidirectional operation")?;

    Ok(BidirectionalForwardResult { nb_a_to_b, nb_b_to_a })
}
