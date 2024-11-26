use anyhow::Context;
use cadeau::xmf::vpx::{decoder::VpxDecoder, encoder::VpxEncoder, VpxCodec};
use tracing::{instrument, trace, warn};
use webm_iterable::{
    errors::TagWriterError,
    matroska_spec::{Master, MatroskaSpec, SimpleBlock},
    WebmWriter, WriteOptions,
};

use crate::debug::mastroka_spec_name;

use super::{block_tag::VideoBlock, StreamingConfig};

const VPX_EFLAG_FORCE_KF: u32 = 0x00000001;

fn write_unknown_sized_element<T>(writer: &mut WebmWriter<T>, tag: &MatroskaSpec) -> Result<(), TagWriterError>
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

    pub fn into_encoded_writer(self, config: EncodeWriterConfig) -> anyhow::Result<CutCusterWriter<T>> {
        let encoded_writer = CutCusterWriter::new(config, self)?;
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

enum CutBlockState {
    HaventMet,
    AtCutBlock,
    // All time here are in unit of millisecond
    // |headers||Cluster Start||Blocks|....|Blocks|..|Blocks||Cluster End||Cluster Start||Blocks|.......|Blocks||Cluster End|.......
    //                                        ￪                                    ￪
    // (absolute timeline)             cut_block_absolute_time            last_block_absolute_time
    //                                        ￪                                    ↓
    //                            |headers||Cluster Start||Blocks|....|Blocks|..|Blocks||Cluster End||Cluster Start||Blocks|.......|Blocks||Cluster End|.......
    //                                        ￪                          ￪                               ￪
    // (relative timeline)             last_cluster_relative_time        ￪                          last_cluster_relative_time
    //                                        ￪--------------------------￪                               ￪
    //                                        ￪                     block timestamp                      ￪
    //                                        ￪  (relative to it's cluster)                              ￪
    //                                        ￪----------------------------------------------------------￪
    //                                             (relative to the cut_block_absolute_time)        last_cluster_relative_time
    //
    //
    Met {
        cut_block_absolute_time: u64,
        // This is the cluster timestamp for the last cluster::timestamp we wrote
        // last_cluster_relative_time + cut_block_absolute_time = the absolute time of original video
        last_cluster_relative_time: u64,
    },
}

pub struct CutCusterWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
    // This is cluster timestamp of the original video, used to construct absolute timeline
    cluster_timestamp: Option<u64>,
    ended: bool,
    encoder: VpxEncoder,
    decoder: VpxDecoder,
    cut_block_state: CutBlockState,
}

impl<T> CutCusterWriter<T>
where
    T: std::io::Write,
{
    fn new(config: EncodeWriterConfig, writer: HeaderWriter<T>) -> anyhow::Result<Self> {
        let decoder = VpxDecoder::builder()
            .threads(config.threads)
            .width(config.width as u32)
            .height(config.height as u32)
            .codec(config.codec)
            .build()?;

        let encoder = VpxEncoder::builder()
            .timebase_num(1)
            .timebase_den(1000)
            .codec(config.codec)
            .width(config.width as u32)
            .height(config.height as u32)
            .threads(config.threads)
            .bitrate(256 * 1024)
            .build()?;

        let HeaderWriter { writer } = writer;
        Ok(Self {
            writer,
            cluster_timestamp: None,
            ended: false,
            encoder,
            decoder,
            cut_block_state: CutBlockState::HaventMet,
        })
    }
}

pub enum WriterResult {
    Finished,
    Continue,
}

impl<T> CutCusterWriter<T>
where
    T: std::io::Write,
{
    #[instrument(skip(self, tag))]
    pub fn write(&mut self, tag: MatroskaSpec) -> anyhow::Result<WriterResult> {
        if self.ended {
            anyhow::bail!("Cannot write after end");
        }

        match tag {
            MatroskaSpec::Timestamp(timestamp) => {
                self.cluster_timestamp = Some(timestamp);
                return Ok(WriterResult::Continue);
            }
            MatroskaSpec::BlockGroup(Master::Full(_)) | MatroskaSpec::SimpleBlock(_) => {}
            MatroskaSpec::BlockGroup(Master::End) | MatroskaSpec::BlockGroup(Master::Start) => {
                // If this happens, check the webm iterator cache tag parameter on new function
                anyhow::bail!("BlockGroup start and end tags are not supported");
            }
            _ => {
                return Ok(WriterResult::Continue);
            }
        }

        let video_block = VideoBlock::new(tag, self.cluster_timestamp)?;

        self.process_current_block(&video_block)?;

        Ok(WriterResult::Continue)
    }

    fn reencode(&mut self, video_block: &VideoBlock, is_key_frame: bool) -> anyhow::Result<Vec<u8>> {
        let frame = video_block.get_frame()?;
        self.decoder.decode(&frame)?;
        {
            let image = self.decoder.next_frame()?;
            self.encoder.encode_frame(
                &image,
                video_block.timestamp.into(),
                30,
                if is_key_frame { VPX_EFLAG_FORCE_KF } else { 0 },
            )?;
        }
        let frame: Vec<u8> = self.encoder.next_frame()?.unwrap();

        Ok(frame)
    }

    fn process_current_block(&mut self, current_video_block: &VideoBlock) -> anyhow::Result<()> {
        let frame = self.reencode(current_video_block, true)?;
        let block = match self.cut_block_state {
            CutBlockState::HaventMet => {
                return Ok(());
            }
            CutBlockState::AtCutBlock => {
                self.start_new_cluster(0)?;
                self.cut_block_state = CutBlockState::Met {
                    cut_block_absolute_time: current_video_block.absolute_timestamp()?,
                    last_cluster_relative_time: 0,
                };
                let block = SimpleBlock::new_uncheked(&frame, 1, 0, false, None, false, true);
                block
            }
            CutBlockState::Met {
                cut_block_absolute_time,
                ..
            } => {
                let current_block_absolute_time = current_video_block.absolute_timestamp()?;
                let cluster_relative_timestamp = current_block_absolute_time - cut_block_absolute_time;
                if self.should_write_new_cluster(current_block_absolute_time) {
                    self.start_new_cluster(cluster_relative_timestamp)?;

                    self.cut_block_state = CutBlockState::Met {
                        cut_block_absolute_time,
                        last_cluster_relative_time: cluster_relative_timestamp,
                    };
                }
                let relative_timestamp = current_video_block.absolute_timestamp()?
                    - cut_block_absolute_time
                    - self.last_cluster_relative_time().unwrap();

                trace!(
                    relative_timestamp,
                    relative_timestamp,
                    cut_block_absolute_time,
                    current_block_absolute_timestamp = current_video_block.absolute_timestamp()?,
                    last_cluster_relative_time = self.last_cluster_relative_time().unwrap()
                );
                let timestamp = i16::try_from(relative_timestamp)?;

                let block = SimpleBlock::new_uncheked(&frame, 1, timestamp, false, None, false, true);
                block
            }
        };

        self.write_block(block)?;
        Ok(())
    }

    fn write_block(&mut self, block: SimpleBlock<'_>) -> anyhow::Result<()> {
        let block: MatroskaSpec = block.into();
        self.writer.write(&block)?;
        Ok(())
    }

    fn start_new_cluster(&mut self, time: u64) -> anyhow::Result<()> {
        if time != 0 {
            self.writer.write(&MatroskaSpec::Cluster(Master::End))?;
        }
        let cluster_start = MatroskaSpec::Cluster(Master::Start);
        let timestamp = MatroskaSpec::Timestamp(time);
        write_unknown_sized_element(&mut self.writer, &cluster_start)?;
        self.writer.write(&timestamp)?;
        self.update_cluster_time(time);
        Ok(())
    }

    fn last_cluster_relative_time(&self) -> Option<u64> {
        if let CutBlockState::Met {
            last_cluster_relative_time,
            ..
        } = &self.cut_block_state
        {
            return Some(*last_cluster_relative_time);
        }

        None
    }

    fn update_cluster_time(&mut self, time: u64) {
        if let CutBlockState::Met {
            ref mut last_cluster_relative_time,
            ..
        } = &mut self.cut_block_state
        {
            // Update the field directly using the mutable reference
            *last_cluster_relative_time = time;
        }
    }

    fn should_write_new_cluster(&self, block_absolute_time: u64) -> bool {
        // When i16 cannot fit the time difference anymore, we need to start a new cluster
        if let CutBlockState::Met {
            cut_block_absolute_time,
            last_cluster_relative_time,
            ..
        } = self.cut_block_state
        {
            // the block time relative to last_cluster_relative_time
            if block_absolute_time - (cut_block_absolute_time + last_cluster_relative_time)
                // i16::Max can always convert to u64
                > u64::try_from(i16::MAX).unwrap()
            {
                return true;
            }
        }
        false
    }

    pub fn mark_cut_block_hit(&mut self) {
        self.cut_block_state = CutBlockState::AtCutBlock;
    }
}

#[derive(Debug)]
pub struct EncodeWriterConfig {
    pub threads: u32,
    pub width: u64,
    pub height: u64,
    pub codec: VpxCodec,
}

pub type Headers<'a> = &'a [MatroskaSpec];

impl TryFrom<(Headers<'_>, &StreamingConfig)> for EncodeWriterConfig {
    type Error = anyhow::Error;

    fn try_from(value: (Headers<'_>, &StreamingConfig)) -> Result<Self, Self::Error> {
        let (value, config) = value;
        let mut width = None;
        let mut height = None;
        let mut codec = None;

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
            threads: config.encoder_threads,
            width: width.ok_or(anyhow::anyhow!("No width specified"))?,
            height: height.ok_or(anyhow::anyhow!("No height specified"))?,
            codec: codec.ok_or(anyhow::anyhow!("No codec specified"))?,
        };

        Ok(config)
    }
}
