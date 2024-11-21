use anyhow::Context;
use cadeau::xmf::vpx::{decoder::VpxDecoder, encoder::VpxEncoder, VpxCodec};
use tracing::{debug, instrument};
use webm_iterable::{
    matroska_spec::{Master, MatroskaSpec, SimpleBlock},
    WebmWriter, WriteOptions,
};

use crate::debug::mastroka_spec_name;

use super::block_tag::VideoBlock;

const VPX_EFLAG_FORCE_KF: u32 = 0x00000001;

fn write_unknown_sized_element<T>(
    writer: &mut WebmWriter<T>,
    tag: &MatroskaSpec,
) -> Result<(), webm_iterable::errors::TagWriterError>
where
    T: std::io::Write,
{
    writer.write_advanced(tag, WriteOptions::is_unknown_sized_element())
}

pub enum WriteResult {
    Written,
    Buffered,
}

pub struct HeaderWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
}

impl<T> HeaderWriter<T>
where
    T: std::io::Write,
{
    pub fn new(writer: T) -> Self {
        Self {
            writer: WebmWriter::new(writer),
        }
    }

    pub fn write(&mut self, tag: &MatroskaSpec) -> anyhow::Result<WriteResult> {
        if let MatroskaSpec::Segment(Master::Start) = tag {
            write_unknown_sized_element(&mut self.writer, tag)
        } else {
            self.writer.write(tag)
        }
        .with_context(|| format!("Failed to write tag: {}", mastroka_spec_name(tag)))?;

        Ok(WriteResult::Written)
    }

    pub fn into_encoded_writer(self, config: EncodeWriterConfig) -> anyhow::Result<EncodedWriter<T>> {
        let encoded_writer = EncodedWriter::new(config, self)?;
        Ok(encoded_writer)
    }
}

#[derive(Debug)]
pub enum EncodeNext {
    ClusterStart,
    Timestamp,
    BlockGroup,
    ClusterEnd,
}

pub struct EncodedWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
    cluster_timestamp: Option<u64>,
    ended: bool,
    encoder: VpxEncoder,
    deocder: VpxDecoder,
    // This is either a BlockGroup(Master::full) or a SimpleBlock
    current_block: Option<MatroskaSpec>,
    cut_block_hit: bool,
    cut_block_processed: bool,

    cut_block_time_offset: Option<u64>,
}

impl<T> EncodedWriter<T>
where
    T: std::io::Write,
{
    fn new(config: EncodeWriterConfig, writer: HeaderWriter<T>) -> anyhow::Result<Self> {
        let deocder = VpxDecoder::builder()
            .threads(config.threads)
            .width(config.width as u32)
            .height(config.height as u32)
            .codec(config.codec)
            .build()?;

        let encoder = VpxEncoder::builder()
            .timebase_num(1)
            .timebase_den(i32::try_from(config.timebase)?)
            .codec(config.codec)
            .width(config.width as u32)
            .height(config.height as u32)
            .threads(config.threads)
            .build()?;

        let HeaderWriter { writer } = writer;
        Ok(Self {
            writer,
            cluster_timestamp: None,
            ended: false,
            encoder,
            deocder,
            current_block: None,
            cut_block_hit: false,
            cut_block_processed: false,
            cut_block_time_offset: None,
        })
    }

    pub fn into_timed_tag_writer(self) -> TimedTagWriter<T> {
        TimedTagWriter::new(self)
    }
}

pub enum EncodedWriteResult {
    Finished,
    Continue,
}

impl<T> EncodedWriter<T>
where
    T: std::io::Write,
{
    #[instrument(skip(self, tag))]
    pub fn write(&mut self, tag: MatroskaSpec) -> anyhow::Result<EncodedWriteResult> {
        let tag_name = mastroka_spec_name(&tag);
        debug!(tag_name, "Encoding tag");

        if self.ended {
            anyhow::bail!("Cannot write after end");
        }

        match tag {
            MatroskaSpec::Timestamp(cluster_timestamp) => {
                if self.cluster_timestamp.is_some() {
                    anyhow::bail!("Time offset already set");
                }
                self.cluster_timestamp = Some(cluster_timestamp);
                return Ok(EncodedWriteResult::Continue);
            }
            MatroskaSpec::Cluster(_) => {
                if self.cluster_timestamp.is_some() {
                    self.ended = true;
                    return Ok(EncodedWriteResult::Finished);
                }
                return Ok(EncodedWriteResult::Continue);
            }
            MatroskaSpec::BlockGroup(Master::Full(_)) | MatroskaSpec::SimpleBlock(_) => {}
            MatroskaSpec::BlockGroup(Master::End) | MatroskaSpec::BlockGroup(Master::Start) => {
                // If this happens, check the webm iterator cache tag parameter on new function
                anyhow::bail!("BlockGroup start and end tags are not supported");
            }
            _ => {
                debug!(tag_name, "Skipping tag");
                return Ok(EncodedWriteResult::Continue);
            }
        }

        let cluster_timestamp = self.cluster_timestamp.context("No cluster timestamp set")?;

        let Some(current_block) = self.current_block.take() else {
            self.current_block = Some(tag);
            return Ok(EncodedWriteResult::Continue);
        };

        let current_video_block = VideoBlock::new(&current_block, cluster_timestamp)?;
        let next_video_block = VideoBlock::new(&tag, cluster_timestamp)?;

        self.process_video_block(&current_video_block, Some(&next_video_block))?;

        self.current_block = Some(tag);

        Ok(EncodedWriteResult::Continue)
    }

    fn process_video_block(
        &mut self,
        current_video_block: &VideoBlock<'_>,
        next_video_block: Option<&VideoBlock<'_>>,
    ) -> anyhow::Result<()> {
        let frame = current_video_block.get_frame()?;
        self.deocder.decode(&frame)?;
        let image = self.deocder.next_frame()?;
        let duration = match next_video_block {
            Some(next_video_block) => {
                next_video_block.absolute_timestamp()? - current_video_block.absolute_timestamp()?
            }
            None => 17,
        };

        let pts = current_video_block.absolute_timestamp()?;

        let flags = if self.cut_block_processed || self.cut_block_hit {
            VPX_EFLAG_FORCE_KF
        } else {
            0
        };

        debug!(?pts, ?duration, "Encoding frame");
        self.encoder
            .encode_frame(&image, pts.try_into()?, duration.try_into()?, flags)?;

        let frame = self.encoder.next_frame()?;

        // We hit the cut block
        if self.cut_block_hit && !self.cut_block_processed {
            self.cut_block_time_offset = Some(current_video_block.absolute_timestamp()?);
            self.cut_block_processed = true;
        }

        // haven't hit the cut block yet, just return
        if !self.cut_block_processed {
            return Ok(());
        }

        let Some(cut_block_time_offset) = self.cut_block_time_offset else {
            anyhow::bail!("Cut block time offset not set");
        };

        let Some(frame) = frame else {
            return Ok(());
        };

        let block_to_write = SimpleBlock::new_uncheked(
            &frame,
            1, // tracks in not necessarily 1, todo: fix this
            (current_video_block.absolute_timestamp()? - cut_block_time_offset).try_into()?,
            false,
            None,
            false,
            true,
        );

        if self.cut_block_hit && !self.cut_block_processed {
            let cluster_start = MatroskaSpec::Cluster(Master::Start);
            write_unknown_sized_element(&mut self.writer, &cluster_start)?;
        }

        debug!(?block_to_write, "Writing block");
        self.writer.write(&MatroskaSpec::from(block_to_write))?;

        Ok(())
    }

    pub fn mark_cut_block_hit(&mut self) {
        self.cut_block_hit = true;
    }
}

#[derive(Debug)]
pub struct EncodeWriterConfig {
    threads: u32,
    width: u64,
    height: u64,
    codec: VpxCodec,
    timebase: u64,
}

pub type Headers<'a> = &'a [MatroskaSpec];

impl TryFrom<Headers<'_>> for EncodeWriterConfig {
    type Error = anyhow::Error;

    fn try_from(value: Headers<'_>) -> Result<Self, Self::Error> {
        let mut width = None;
        let mut height = None;
        let mut codec = None;
        let mut timebase = None;

        for header in value {
            match header {
                MatroskaSpec::CodecID(codec_id) => match codec_id.as_str() {
                    "V_VP8" | "vp8" => {
                        codec = Some(VpxCodec::VP8);
                    }
                    "V_VP9" | "vp9" => codec = Some(VpxCodec::VP9),
                    _ => {
                        anyhow::bail!("Unknown codec: {}", codec_id);
                    }
                },
                MatroskaSpec::TimestampScale(scale) => {
                    timebase = Some(*scale);
                }
                MatroskaSpec::PixelWidth(w) => {
                    width = Some(*w);
                }
                MatroskaSpec::PixelHeight(h) => {
                    height = Some(*h);
                }
                _ => {}
            }
        }

        let config = EncodeWriterConfig {
            threads: 4, // To be determined
            width: width.ok_or(anyhow::anyhow!("No width specified"))?,
            height: height.ok_or(anyhow::anyhow!("No height specified"))?,
            codec: codec.ok_or(anyhow::anyhow!("No codec specified"))?,
            timebase: timebase.ok_or(anyhow::anyhow!("No timebase specified"))?,
        };

        Ok(config)
    }
}

pub struct TimedTagWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
    time_offset: u64,
}

impl<T> TimedTagWriter<T>
where
    T: std::io::Write,
{
    fn new(encoded_writer: EncodedWriter<T>) -> Self {
        let EncodedWriter {
            writer,
            cut_block_time_offset,
            ..
        } = encoded_writer;

        Self {
            writer,
            time_offset: cut_block_time_offset.unwrap_or(0),
        }
    }

    pub fn write(&mut self, tag: MatroskaSpec) -> anyhow::Result<()> {
        let tag = match tag {
            MatroskaSpec::Timestamp(timestamp) => MatroskaSpec::Timestamp(timestamp - self.time_offset),
            _ => tag,
        };

        if let MatroskaSpec::Cluster(Master::Start) = tag {
            write_unknown_sized_element(&mut self.writer, &tag)
        } else {
            self.writer.write(&tag)
        }?;

        Ok(())
    }
}
