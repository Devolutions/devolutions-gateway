use std::io::{Seek, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use webm_iterable::WebmIterator;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

use crate::StreamingConfig;
use crate::reopenable::Reopenable;
use crate::streamer::iter::{IteratorError, WebmPositionedIterator};
use crate::streamer::tag_writers::{EncodeWriterConfig, HeaderWriter, WriterResult};

#[derive(Debug, Clone)]
pub struct ReencodeBenchStats {
    pub wall: Duration,
    pub tags_processed: u64,
    pub frames_reencoded: u64,
    pub input_media_span_ms: u64,
    pub chunks_written: u64,
    pub bytes_written: u64,
    pub timed_out: bool,
}

#[derive(Default)]
struct CountingWriter {
    chunks: u64,
    bytes: u64,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.chunks += 1;
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bench helper: re-encode the first `max_tags` relevant tags from a WebM file and measure wall-clock time.
///
/// Notes:
/// - This uses the same WebM parsing + VPX decoder/encoder path as `webm_stream`, but writes output to a counting sink.
/// - Requires XMF to be initialized by the caller (e.g. `cadeau::xmf::init(...)`).
pub fn reencode_first_tags<R>(
    input_stream: R,
    config: StreamingConfig,
    max_tags: u64,
) -> anyhow::Result<ReencodeBenchStats>
where
    R: std::io::Read + Seek + Reopenable,
{
    reencode_first_tags_until_deadline(input_stream, config, max_tags, None)
}

/// Bench helper: re-encode up to `max_tags`, but stop early if `max_wall` elapses.
///
/// This is intended for "sane timeout" local diagnosis: it prevents benches from running forever on slow machines.
pub fn reencode_first_tags_until_deadline<R>(
    input_stream: R,
    config: StreamingConfig,
    max_tags: u64,
    max_wall: Option<Duration>,
) -> anyhow::Result<ReencodeBenchStats>
where
    R: std::io::Read + Seek + Reopenable,
{
    let started_at = Instant::now();

    let mut webm_itr = WebmPositionedIterator::new(WebmIterator::new(
        input_stream,
        &[MatroskaSpec::BlockGroup(Master::Start)],
    ));

    let mut headers = vec![];
    while let Some(tag) = webm_itr.next() {
        let tag = tag?;
        if matches!(tag, MatroskaSpec::Cluster(Master::Start)) {
            break;
        }
        headers.push(tag);
    }

    let encode_writer_config = EncodeWriterConfig::try_from((headers.as_slice(), &config))?;

    let mut sink = CountingWriter::default();
    let mut header_writer = HeaderWriter::new(&mut sink);
    for header in &headers {
        header_writer.write(header)?;
    }

    let (mut encode_writer, _marker) = header_writer.into_encoded_writer(encode_writer_config)?;

    let mut tags_processed: u64 = 0;
    let mut cluster_timestamp: Option<u64> = None;
    let mut first_input_block_absolute_time: Option<u64> = None;
    let mut last_input_block_absolute_time: Option<u64> = None;
    let mut frames_reencoded: u64 = 0;
    let mut timed_out = false;
    while tags_processed < max_tags {
        if let Some(max_wall) = max_wall
            && max_wall <= started_at.elapsed()
        {
            timed_out = true;
            break;
        }

        match webm_itr.next() {
            Some(Ok(tag)) => {
                match &tag {
                    MatroskaSpec::Timestamp(timestamp) => cluster_timestamp = Some(*timestamp),
                    MatroskaSpec::SimpleBlock(data) => {
                        if let Some(cluster_timestamp) = cluster_timestamp {
                            let simple_block = SimpleBlock::try_from(data)?;
                            let abs_ms_i64 = i64::try_from(cluster_timestamp)
                                .context("cluster timestamp does not fit in i64")?
                                .checked_add(i64::from(simple_block.timestamp))
                                .context("block absolute timestamp overflow")?;
                            let abs_ms =
                                u64::try_from(abs_ms_i64).context("block absolute timestamp does not fit in u64")?;
                            first_input_block_absolute_time.get_or_insert(abs_ms);
                            last_input_block_absolute_time = Some(abs_ms);
                            frames_reencoded += 1;
                        }
                    }
                    MatroskaSpec::BlockGroup(Master::Full(children)) => {
                        if let Some(cluster_timestamp) = cluster_timestamp {
                            let raw_block = children.iter().find_map(|t| match t {
                                MatroskaSpec::Block(block) => Some(block),
                                _ => None,
                            });

                            if let Some(raw_block) = raw_block {
                                let block = Block::try_from(raw_block)?;
                                let abs_ms_i64 = i64::try_from(cluster_timestamp)
                                    .context("cluster timestamp does not fit in i64")?
                                    .checked_add(i64::from(block.timestamp))
                                    .context("block absolute timestamp overflow")?;
                                let abs_ms = u64::try_from(abs_ms_i64)
                                    .context("block absolute timestamp does not fit in u64")?;
                                first_input_block_absolute_time.get_or_insert(abs_ms);
                                last_input_block_absolute_time = Some(abs_ms);
                                frames_reencoded += 1;
                            }
                        }
                    }
                    _ => {}
                }

                tags_processed += 1;
                match encode_writer.write(tag)? {
                    WriterResult::Continue => {}
                }
            }
            Some(Err(IteratorError::InnerError(TagIteratorError::UnexpectedEOF { .. }))) => break,
            Some(Err(e)) => return Err(e).context("webm iterator error"),
            None => break,
        }
    }

    let input_media_span_ms = last_input_block_absolute_time
        .zip(first_input_block_absolute_time)
        .map(|(last, first)| last.saturating_sub(first))
        .unwrap_or(0);

    Ok(ReencodeBenchStats {
        wall: started_at.elapsed(),
        tags_processed,
        frames_reencoded,
        input_media_span_ms,
        chunks_written: sink.chunks,
        bytes_written: sink.bytes,
        timed_out,
    })
}

/// Bench helper: open a WebM file from disk and re-encode.
///
/// Notes:
/// - This is a convenience wrapper for Criterion benches.
pub fn reencode_first_tags_from_path(
    input_path: &Path,
    config: StreamingConfig,
    max_tags: u64,
) -> anyhow::Result<ReencodeBenchStats> {
    let file = crate::streamer::reopenable_file::ReOpenableFile::open(input_path)
        .with_context(|| format!("failed to open {}", input_path.display()))?;
    reencode_first_tags(file, config, max_tags)
}

pub fn reencode_first_tags_from_path_until_deadline(
    input_path: &Path,
    config: StreamingConfig,
    max_tags: u64,
    max_wall: Duration,
) -> anyhow::Result<ReencodeBenchStats> {
    let file = crate::streamer::reopenable_file::ReOpenableFile::open(input_path)
        .with_context(|| format!("failed to open {}", input_path.display()))?;
    reencode_first_tags_until_deadline(file, config, max_tags, Some(max_wall))
}
