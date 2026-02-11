use std::time::Instant;

use anyhow::Context;
use cadeau::xmf::vpx::{VpxCodec, VpxDecoder, VpxEncoder};
use webm_iterable::errors::TagWriterError;
use webm_iterable::matroska_spec::{Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmWriter, WriteOptions};

use super::block_tag::VideoBlock;
use super::channel_writer::ChannelWriterError;
use crate::StreamingConfig;
use crate::debug::mastroka_spec_name;

const VPX_EFLAG_FORCE_KF: u32 = 0x00000001;

#[cfg(feature = "perf-diagnostics")]
fn duration_as_millis_u64(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn write_unknown_sized_element<T>(writer: &mut WebmWriter<T>, tag: &MatroskaSpec) -> Result<(), TagWriterError>
where
    T: std::io::Write,
{
    writer.write_advanced(tag, WriteOptions::is_unknown_sized_element())
}

pub(crate) struct HeaderWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
}

impl<T> HeaderWriter<T>
where
    T: std::io::Write,
{
    pub(crate) fn new(writer: T) -> Self {
        Self {
            writer: WebmWriter::new(writer),
        }
    }

    pub(crate) fn write(&mut self, tag: &MatroskaSpec) -> anyhow::Result<()> {
        if let MatroskaSpec::Segment(Master::Start) = tag {
            write_unknown_sized_element(&mut self.writer, tag)
        } else {
            self.writer.write(tag)
        }
        .with_context(|| format!("failed to write tag: {}", mastroka_spec_name(tag)))?;

        Ok(())
    }

    pub(crate) fn into_encoded_writer(
        self,
        config: EncodeWriterConfig,
    ) -> anyhow::Result<(CutClusterWriter<T>, CutBlockHitMarker)> {
        let encoded_writer = CutClusterWriter::new(config, self)?;
        Ok(encoded_writer)
    }
}

#[derive(Debug, Clone, Copy)]
enum CutBlockState {
    HaventMet,
    AtCutBlock,
    // All times here are in units of milliseconds.
    //             |headers||Cluster Start||Blocks|....|Blocks|..|Blocks||Cluster End||Cluster Start||Blocks|.......|Blocks||Cluster End|.......
    //                        ￪                           ￪                                    ￪
    //(absolute timeline)     ￪                 cut_block_absolute_time            last_block_absolute_time
    //                        ￪                           ￪                                    ↓
    //                        ￪               |headers||Cluster Start||Blocks|....|Blocks|..|Blocks||Cluster End||Cluster Start||Blocks|.......|Blocks||Cluster End|.......
    //                        ￪                           ￪                          ￪                               ￪
    //(relative timeline)     ￪           (1st) last_cluster_relative_time           ￪            (2nd) last_cluster_relative_time
    //                        ￪                           ￪--------------------------￪                               ￪
    //                        ￪                           ￪                     block timestamp                      ￪
    //                        ￪                           ￪  (relative to its cluster)                               ￪
    //                        ￪                           ￪----------------------------------------------------------￪
    //                        ￪                           ￪    (relative to the cut_block_absolute_time)        last_cluster_relative_time
    //    beginning of the absolute timeline              ￪
    //                        ￪               beginning of the relative timeline
    //                        ￪---------------------------￪
    //                        offset between the two timelines
    //                        defined by the cut_block_absolute_time
    Met {
        cut_block_absolute_time: u64,
        // This is the cluster timestamp for the last cluster::timestamp we wrote
        // last_cluster_relative_time + cut_block_absolute_time = the absolute time of original video
        last_cluster_relative_time: u64,
    },
}

pub(crate) struct CutClusterWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
    // This is cluster timestamp of the original video, used to construct absolute timeline
    cluster_timestamp: Option<u64>,
    encoder: VpxEncoder,
    decoder: VpxDecoder,
    cut_block_state: CutBlockState,
    last_encoded_abs_time: Option<u64>,

    // Adaptive frame skipping state
    stream_start: Instant,
    last_ratio: f64,
    frames_since_last_encode: u32,
    adaptive_frame_skip: bool,

    #[cfg(feature = "perf-diagnostics")]
    last_report_at: Instant,
    #[cfg(feature = "perf-diagnostics")]
    frames_reencoded: u64,
}

/// A token type that enforces the one-time transition of cut block state.
pub(crate) struct CutBlockHitMarker;

impl<T> CutClusterWriter<T>
where
    T: std::io::Write,
{
    fn new(config: EncodeWriterConfig, writer: HeaderWriter<T>) -> anyhow::Result<(Self, CutBlockHitMarker)> {
        perf_trace!(
            width = config.width,
            height = config.height,
            threads = config.threads,
            codec = ?config.codec,
            "CutClusterWriter::new - building VPX decoder"
        );

        let decoder = VpxDecoder::builder()
            .threads(config.threads)
            .width(config.width)
            .height(config.height)
            .codec(config.codec)
            .build()
            .inspect_err(|error| {
                error!(
                    error = %error,
                    width = config.width,
                    height = config.height,
                    threads = config.threads,
                    codec = ?config.codec,
                    "VpxDecoder build failed"
                );
            })?;

        perf_trace!(
            width = config.width,
            height = config.height,
            threads = config.threads,
            codec = ?config.codec,
            bitrate = 256 * 1024,
            timebase_num = 1,
            timebase_den = 1000,
            "CutClusterWriter::new - building VPX encoder"
        );

        let encoder = VpxEncoder::builder()
            .timebase_num(1)
            .timebase_den(1000)
            .codec(config.codec)
            .width(config.width)
            .height(config.height)
            .threads(config.threads)
            .bitrate(256 * 1024)
            .build()
            .inspect_err(|error| {
                error!(
                    error = %error,
                    width = config.width,
                    height = config.height,
                    threads = config.threads,
                    codec = ?config.codec,
                    bitrate = 256 * 1024,
                    "VpxEncoder build failed - this is likely VpxCodecInvalidParam"
                );
            })?;

        perf_trace!("CutClusterWriter created successfully - decoder and encoder initialized");

        let HeaderWriter { writer } = writer;
        Ok((
            Self {
                writer,
                cluster_timestamp: None,
                encoder,
                decoder,
                cut_block_state: CutBlockState::HaventMet,
                last_encoded_abs_time: None,
                stream_start: Instant::now(),
                last_ratio: 1.0,
                frames_since_last_encode: 0,
                adaptive_frame_skip: config.adaptive_frame_skip,
                #[cfg(feature = "perf-diagnostics")]
                last_report_at: Instant::now(),
                #[cfg(feature = "perf-diagnostics")]
                frames_reencoded: 0,
            },
            CutBlockHitMarker,
        ))
    }

    fn decode_only(&mut self, current_video_block: &VideoBlock) -> anyhow::Result<()> {
        self.decoder.decode(&current_video_block.get_frame()?)?;
        Ok(())
    }
}

pub(crate) enum WriterResult {
    Continue,
}

impl<T> CutClusterWriter<T>
where
    T: std::io::Write,
{
    #[instrument(skip(self, tag))]
    pub(crate) fn write(&mut self, tag: MatroskaSpec) -> anyhow::Result<WriterResult> {
        let tag_name = mastroka_spec_name(&tag);
        perf_trace!(
            tag_name = %tag_name,
            cluster_timestamp = ?self.cluster_timestamp,
            cut_block_state = ?self.cut_block_state,
            "CutClusterWriter::write called"
        );

        match tag {
            MatroskaSpec::Timestamp(timestamp) => {
                perf_trace!(
                    timestamp,
                    previous_cluster_timestamp = ?self.cluster_timestamp,
                    "Updating cluster_timestamp"
                );
                self.cluster_timestamp = Some(timestamp);
                return Ok(WriterResult::Continue);
            }
            MatroskaSpec::BlockGroup(Master::Full(_)) | MatroskaSpec::SimpleBlock(_) => {
                perf_trace!(tag_name = %tag_name, "Processing block tag");
            }
            MatroskaSpec::BlockGroup(Master::End) | MatroskaSpec::BlockGroup(Master::Start) => {
                error!(
                    tag_name = %tag_name,
                    "Unsupported BlockGroup Start/End tag received"
                );
                // If this happens, check the WebM iterator cache tag parameter on the new function.
                anyhow::bail!("blockGroup start and end tags are not supported");
            }
            _ => {
                perf_trace!(tag_name = %tag_name, "Skipping non-block tag");
                return Ok(WriterResult::Continue);
            }
        }

        let video_block = VideoBlock::new(tag, self.cluster_timestamp)?;
        perf_trace!(
            block_timestamp = video_block.timestamp,
            cluster_timestamp = ?self.cluster_timestamp,
            "VideoBlock created"
        );

        self.process_current_block(&video_block)?;

        Ok(WriterResult::Continue)
    }

    fn reencode(
        &mut self,
        video_block: &VideoBlock,
        is_key_frame: bool,
        duration: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let timestamp = video_block.timestamp;
        let flags = if is_key_frame { VPX_EFLAG_FORCE_KF } else { 0 };

        #[cfg(feature = "perf-diagnostics")]
        let decode_started_at = Instant::now();
        perf_trace!(
            timestamp,
            is_key_frame,
            flags,
            "Reencode: getting frame from video block"
        );

        let frame = video_block.get_frame()?;
        let frame_size = frame.len();
        perf_trace!(frame_size, timestamp, "Reencode: decoding frame");

        self.decoder.decode(&frame).inspect_err(|error| {
            error!(
                error = %error,
                frame_size,
                timestamp,
                "VPX decoder.decode() failed"
            );
        })?;

        {
            #[cfg(feature = "perf-diagnostics")]
            let decode_ms = duration_as_millis_u64(decode_started_at.elapsed());
            #[cfg(feature = "perf-diagnostics")]
            let encode_started_at = Instant::now();
            let image = self.decoder.next_frame().inspect_err(|error| {
                error!(error = %error, timestamp, "VPX decoder.next_frame() failed");
            })?;

            perf_trace!(timestamp, is_key_frame, flags, duration, "Reencode: encoding frame");

            self.encoder
                .encode_frame(&image, video_block.timestamp.into(), duration, flags)
                .inspect_err(|error| {
                    error!(
                        error = %error,
                        timestamp,
                        is_key_frame,
                        flags,
                        "VPX encoder.encode_frame() failed - likely VpxCodecInvalidParam"
                    );
                })?;

            #[cfg(feature = "perf-diagnostics")]
            {
                let encode_ms = duration_as_millis_u64(encode_started_at.elapsed());
                let wall_elapsed_ms = duration_as_millis_u64(self.stream_start.elapsed());
                self.frames_reencoded += 1;

                // PERF-HYPOTHESIS: This log is intended to prove/disprove whether decode+encode throughput is too slow
                // to follow the recording in near real-time.
                if encode_ms >= 50 || self.frames_reencoded.is_multiple_of(30) {
                    info!(
                        prefix = "[LibVPx-Performance-Hypothesis]",
                        frames_reencoded = self.frames_reencoded,
                        wall_elapsed_ms,
                        decode_ms,
                        encode_ms,
                        force_kf = (flags & VPX_EFLAG_FORCE_KF) != 0,
                        input_frame_bytes = frame_size,
                        "Reencode timing"
                    );
                } else {
                    perf_trace!(
                        prefix = "[LibVPx-Performance-Hypothesis]",
                        frames_reencoded = self.frames_reencoded,
                        wall_elapsed_ms,
                        decode_ms,
                        encode_ms,
                        force_kf = (flags & VPX_EFLAG_FORCE_KF) != 0,
                        input_frame_bytes = frame_size,
                        "Reencode timing"
                    );
                }
            }
        }

        let frame = self.encoder.next_frame().inspect_err(|error| {
            error!(error = %error, timestamp, "VPX encoder.next_frame() failed");
        })?;

        perf_trace!(
            timestamp,
            output_frame_size = frame.as_ref().map(|f| f.len()),
            "Reencode completed"
        );

        Ok(frame)
    }

    fn current_realtime_ratio(&self, media_advanced_ms: u64) -> f64 {
        #[allow(clippy::cast_possible_truncation)] // u64 max is ~584 million years in ms; no real truncation risk
        let wall_ms = self.stream_start.elapsed().as_millis() as u64;
        if wall_ms == 0 {
            1.0
        } else {
            media_advanced_ms as f64 / wall_ms as f64
        }
    }

    fn should_skip_encode(&self) -> bool {
        // Skip encoding when falling behind real-time. The ratio naturally self-regulates:
        // skipping makes processing faster (decode-only), which pushes ratio back above 1.0,
        // which resumes encoding. This bang-bang control keeps the stream near real-time.
        self.adaptive_frame_skip && self.last_ratio < 1.0
    }

    #[cfg(feature = "perf-diagnostics")]
    fn maybe_report_realtime_ratio(&mut self, current_block_absolute_time: u64, media_advanced_ms: u64) {
        self.last_ratio = self.current_realtime_ratio(media_advanced_ms);

        // Report at most once per second to keep logs readable.
        if self.last_report_at.elapsed().as_secs_f32() < 1.0 {
            return;
        }
        self.last_report_at = Instant::now();

        let wall_elapsed_ms = duration_as_millis_u64(self.stream_start.elapsed());

        info!(
            prefix = "[LibVPx-Performance-Hypothesis]",
            wall_elapsed_ms,
            current_block_absolute_time,
            media_advanced_ms,
            realtime_ratio = self.last_ratio,
            frames_reencoded = self.frames_reencoded,
            "Stream advancement"
        );
    }

    #[cfg(not(feature = "perf-diagnostics"))]
    fn maybe_report_realtime_ratio(&mut self, _current_block_absolute_time: u64, media_advanced_ms: u64) {
        self.last_ratio = self.current_realtime_ratio(media_advanced_ms);
    }

    fn process_current_block(&mut self, current_video_block: &VideoBlock) -> anyhow::Result<()> {
        #[cfg(feature = "perf-diagnostics")]
        let block_timestamp = current_video_block.timestamp;
        perf_trace!(
            block_timestamp,
            cut_block_state = ?self.cut_block_state,
            "Processing current block"
        );

        match self.cut_block_state {
            CutBlockState::HaventMet => {
                perf_trace!(block_timestamp, "State is HaventMet - decoding block without writing");
                self.decode_only(current_video_block)?;
                return Ok(());
            }
            CutBlockState::AtCutBlock => {
                let abs_time = current_video_block.absolute_timestamp()?;
                let duration = self.compute_encode_duration(abs_time);
                let frame = self.reencode(current_video_block, true, duration)?;
                let Some(frame) = frame else {
                    perf_trace!(block_timestamp, "No frame available from encoder - skipping");
                    return Ok(());
                };

                #[cfg(feature = "perf-diagnostics")]
                let frame_size = frame.len();
                perf_trace!(block_timestamp, frame_size, "Frame available from encoder");

                let cut_block_absolute_time = abs_time;
                perf_trace!(
                    block_timestamp,
                    cut_block_absolute_time,
                    "State AtCutBlock - starting new cluster at time 0"
                );
                self.start_new_cluster(0)?;
                self.cut_block_state = CutBlockState::Met {
                    cut_block_absolute_time,
                    last_cluster_relative_time: 0,
                };
                perf_trace!(cut_block_absolute_time, "State transition: AtCutBlock -> Met");

                let block = SimpleBlock::new_uncheked(&frame, 1, 0, false, None, false, true);
                perf_trace!(block_timestamp, "Writing block to output");
                self.write_block(block)?;
                self.last_encoded_abs_time = Some(abs_time);
            }
            CutBlockState::Met {
                cut_block_absolute_time,
                ..
            } => {
                let abs_time = current_video_block.absolute_timestamp()?;
                let media_advanced_ms = abs_time.saturating_sub(cut_block_absolute_time);
                self.last_ratio = self.current_realtime_ratio(media_advanced_ms);

                if self.should_skip_encode() {
                    perf_trace!(
                        block_timestamp,
                        frames_since_last_encode = self.frames_since_last_encode,
                        last_ratio = %self.last_ratio,
                        "Frame skipped - decode only, encode deferred"
                    );
                    self.decode_only(current_video_block)?;
                    self.frames_since_last_encode += 1;
                    return Ok(());
                }

                perf_trace!(
                    block_timestamp,
                    frames_skipped = self.frames_since_last_encode,
                    last_ratio = %self.last_ratio,
                    "Encoding frame after skip burst"
                );
                self.frames_since_last_encode = 0;

                let duration = self.compute_encode_duration(abs_time);
                let frame = self.reencode(current_video_block, false, duration)?;
                let Some(frame) = frame else {
                    perf_trace!(block_timestamp, "No frame available from encoder - skipping");
                    return Ok(());
                };

                #[cfg(feature = "perf-diagnostics")]
                let frame_size = frame.len();
                perf_trace!(block_timestamp, frame_size, "Frame available from encoder");

                let timestamp = self.compute_met_timestamp(cut_block_absolute_time, abs_time)?;
                let block = SimpleBlock::new_uncheked(&frame, 1, timestamp, false, None, false, false);
                perf_trace!(block_timestamp, "Writing block to output");
                self.write_block(block)?;
                self.last_encoded_abs_time = Some(abs_time);
            }
        }

        Ok(())
    }

    fn compute_encode_duration(&self, abs_time: u64) -> usize {
        let duration_ms = match self.last_encoded_abs_time {
            Some(last_abs_time) => abs_time.saturating_sub(last_abs_time).max(1),
            None => 30,
        };

        usize::try_from(duration_ms).unwrap_or(usize::MAX)
    }

    fn compute_met_timestamp(&mut self, cut_block_absolute_time: u64, abs_time: u64) -> anyhow::Result<i16> {
        let cluster_rel = abs_time - cut_block_absolute_time;

        self.maybe_report_realtime_ratio(abs_time, cluster_rel);

        if self.should_write_new_cluster(abs_time) {
            perf_trace!(abs_time, cluster_rel, "Starting new cluster due to timestamp overflow");
            self.start_new_cluster(cluster_rel)?;
            self.cut_block_state = CutBlockState::Met {
                cut_block_absolute_time,
                last_cluster_relative_time: cluster_rel,
            };
        }

        let last_cluster_rel = self
            .last_cluster_relative_time()
            .context("missing last cluster relative time")?;
        let relative = abs_time - cut_block_absolute_time - last_cluster_rel;

        perf_trace!(
            relative,
            cut_block_absolute_time,
            current_block_absolute_timestamp = abs_time,
            last_cluster_relative_time = last_cluster_rel,
            "Calculated block relative timestamp"
        );

        i16::try_from(relative)
            .inspect_err(|error| {
                error!(
                    error = %error,
                    relative_timestamp = relative,
                    "Relative timestamp i16 overflow"
                );
            })
            .map_err(Into::into)
    }

    fn write_block(&mut self, block: SimpleBlock<'_>) -> anyhow::Result<()> {
        perf_trace!("write_block - converting SimpleBlock to MatroskaSpec");
        let block: MatroskaSpec = block.into();
        if let Err(e) = self.writer.write(&block) {
            // When the client disconnects or we are shutting down, the destination channel is closed.
            // This is normal control flow and is handled at a higher level.
            if let TagWriterError::WriteError { source } = &e
                && source.kind() == std::io::ErrorKind::Other
                && source
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<ChannelWriterError>())
                    .is_some_and(|inner| matches!(inner, &ChannelWriterError::ChannelClosed))
            {
                perf_trace!("write_block aborted - destination channel closed");
                return Err(e.into());
            }

            error!(error = %e, "write_block failed");
            return Err(e.into());
        }
        perf_trace!("write_block completed successfully");
        Ok(())
    }

    fn start_new_cluster(&mut self, time: u64) -> anyhow::Result<()> {
        perf_trace!(time, is_first_cluster = (time == 0), "start_new_cluster called");

        if time != 0 {
            perf_trace!("Writing Cluster::End for previous cluster");
            self.writer.write(&MatroskaSpec::Cluster(Master::End))?;
        }
        let cluster_start = MatroskaSpec::Cluster(Master::Start);
        let timestamp = MatroskaSpec::Timestamp(time);
        perf_trace!(time, "Writing Cluster::Start and Timestamp");
        write_unknown_sized_element(&mut self.writer, &cluster_start)?;
        self.writer.write(&timestamp)?;
        self.update_cluster_time(time);
        perf_trace!(time, "start_new_cluster completed");
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
            last_cluster_relative_time,
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
                > u64::try_from(i16::MAX).expect("unreachable, i16::MAX is always a valid u64")
            {
                return true;
            }
        }
        false
    }

    pub(crate) fn mark_cut_block_hit(&mut self, _marker: CutBlockHitMarker) {
        perf_trace!(
            previous_state = ?format!("{:?}", match &self.cut_block_state {
                CutBlockState::HaventMet => "HaventMet",
                CutBlockState::AtCutBlock => "AtCutBlock",
                CutBlockState::Met { .. } => "Met",
            }),
            "mark_cut_block_hit called - transitioning to AtCutBlock"
        );
        self.cut_block_state = CutBlockState::AtCutBlock;
        perf_trace!("Cut block state is now AtCutBlock");
    }
}

#[derive(Debug)]
pub(crate) struct EncodeWriterConfig {
    pub threads: u32,
    pub width: u32,
    pub height: u32,
    pub codec: VpxCodec,
    pub adaptive_frame_skip: bool,
}

pub(crate) type Headers<'a> = &'a [MatroskaSpec];

impl TryFrom<(Headers<'_>, &StreamingConfig)> for EncodeWriterConfig {
    type Error = anyhow::Error;

    fn try_from(value: (Headers<'_>, &StreamingConfig)) -> Result<Self, Self::Error> {
        let (value, config) = value;
        let mut width = None;
        let mut height = None;
        let mut codec = None;

        perf_trace!(
            headers_count = value.len(),
            encoder_threads = config.encoder_threads.value,
            "EncodeWriterConfig::try_from - parsing headers"
        );

        for header in value {
            match header {
                MatroskaSpec::CodecID(codec_id) => {
                    perf_trace!(codec_id = %codec_id, "Found CodecID header");
                    match codec_id.as_str() {
                        "V_VP8" | "vp8" => {
                            perf_trace!("Codec identified as VP8");
                            codec = Some(VpxCodec::VP8);
                        }
                        "V_VP9" | "vp9" => {
                            perf_trace!("Codec identified as VP9");
                            codec = Some(VpxCodec::VP9);
                        }
                        _ => {
                            error!(codec_id = %codec_id, "Unknown codec in headers");
                            anyhow::bail!("unknown codec: {}", codec_id);
                        }
                    }
                }
                MatroskaSpec::PixelWidth(w) => {
                    perf_trace!(width = w, "Found PixelWidth header");
                    width = Some(*w);
                }
                MatroskaSpec::PixelHeight(h) => {
                    perf_trace!(height = h, "Found PixelHeight header");
                    height = Some(*h);
                }
                _ => {}
            }
        }

        perf_trace!(
            width = ?width,
            height = ?height,
            codec = ?codec,
            "Header parsing complete - creating config"
        );

        let threads = config
            .encoder_threads
            .value
            .try_into()
            .context("invalid thread count")?;

        let final_width = width.map(u32::try_from).context("no width specified in headers")??;
        let final_height = height.map(u32::try_from).context("no height specified in headers")??;
        let final_codec = codec.context("no codec specified in headers")?;

        let config = EncodeWriterConfig {
            threads,
            width: final_width,
            height: final_height,
            codec: final_codec,
            adaptive_frame_skip: config.adaptive_frame_skip,
        };

        perf_debug!(
            width = config.width,
            height = config.height,
            threads = config.threads,
            codec = ?config.codec,
            "EncodeWriterConfig created from headers"
        );

        Ok(config)
    }
}
