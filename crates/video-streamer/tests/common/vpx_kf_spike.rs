use std::convert::TryInto as _;
use std::io::BufReader;

use cadeau::xmf::vpx::{VpxCodec, is_key_frame};
use webm_iterable::WebmIterator;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

#[derive(Debug, Clone)]
pub(crate) struct FrameAt {
    pub(crate) abs_ms: u64,
    pub(crate) is_key_frame: bool,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VpxStreamConfig {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) codec: VpxCodec,
}

pub(crate) fn parse_vpx_config_from_headers(headers: &[MatroskaSpec]) -> anyhow::Result<VpxStreamConfig> {
    let mut width: Option<u32> = None;
    let mut height: Option<u32> = None;
    let mut codec: Option<VpxCodec> = None;

    for header in headers {
        match header {
            MatroskaSpec::CodecID(codec_id) => {
                codec = Some(match codec_id.as_str() {
                    "V_VP8" | "vp8" => VpxCodec::VP8,
                    "V_VP9" | "vp9" => VpxCodec::VP9,
                    _ => anyhow::bail!("unknown codec: {codec_id}"),
                });
            }
            MatroskaSpec::PixelWidth(w) => width = Some((*w).try_into()?),
            MatroskaSpec::PixelHeight(h) => height = Some((*h).try_into()?),
            _ => {}
        }
    }

    Ok(VpxStreamConfig {
        width: width.ok_or_else(|| anyhow::anyhow!("missing PixelWidth in headers"))?,
        height: height.ok_or_else(|| anyhow::anyhow!("missing PixelHeight in headers"))?,
        codec: codec.ok_or_else(|| anyhow::anyhow!("missing CodecID in headers"))?,
    })
}

pub(crate) fn read_headers_and_frames_until(
    path: &std::path::Path,
    end_ms: u64,
) -> anyhow::Result<(VpxStreamConfig, Vec<FrameAt>)> {
    let file = std::fs::File::open(path)?;
    let mut itr = WebmIterator::new(BufReader::new(file), &[]);
    itr.emit_master_end_when_eof(false);

    let mut headers = Vec::<MatroskaSpec>::new();
    let mut in_cluster = false;
    let mut current_cluster_ts: Option<u64> = None;
    let mut frames = Vec::<FrameAt>::new();

    for tag in &mut itr {
        match tag {
            Ok(MatroskaSpec::Cluster(Master::Start)) => {
                in_cluster = true;
                current_cluster_ts = None;
            }
            Ok(MatroskaSpec::Cluster(Master::End)) => {
                in_cluster = false;
                current_cluster_ts = None;
            }
            Ok(MatroskaSpec::Timestamp(ts)) => {
                if in_cluster {
                    current_cluster_ts = Some(ts);
                } else {
                    headers.push(MatroskaSpec::Timestamp(ts));
                }
            }
            Ok(tag @ MatroskaSpec::BlockGroup(_))
            | Ok(tag @ MatroskaSpec::SimpleBlock(_))
            | Ok(tag @ MatroskaSpec::CodecID(_))
            | Ok(tag @ MatroskaSpec::PixelWidth(_))
            | Ok(tag @ MatroskaSpec::PixelHeight(_)) => {
                if !in_cluster {
                    headers.push(tag);
                    continue;
                }

                let Some(cluster_ts) = current_cluster_ts else {
                    continue;
                };

                let (block_ts, is_kf, frame) = match &tag {
                    MatroskaSpec::SimpleBlock(data) => {
                        let sb = SimpleBlock::try_from(data)?;
                        let mut frames = sb.read_frame_data()?;
                        if frames.len() != 1 {
                            anyhow::bail!("laced SimpleBlock not supported (frames={})", frames.len());
                        }
                        let frame = frames.pop().expect("len checked").data.to_vec();
                        (sb.timestamp, sb.keyframe, frame)
                    }
                    MatroskaSpec::BlockGroup(Master::Full(children)) => {
                        let raw_block = children
                            .iter()
                            .find_map(|t| if let MatroskaSpec::Block(b) = t { Some(b) } else { None })
                            .ok_or_else(|| anyhow::anyhow!("BlockGroup missing Block"))?;
                        let block = Block::try_from(raw_block)?;
                        let mut frames = block.read_frame_data()?;
                        if frames.len() != 1 {
                            anyhow::bail!("laced BlockGroup not supported (frames={})", frames.len());
                        }
                        let frame = frames.pop().expect("len checked").data.to_vec();
                        let is_kf = is_key_frame(&frame);
                        (block.timestamp, is_kf, frame)
                    }
                    _ => continue,
                };

                let cluster_ts_i64 =
                    i64::try_from(cluster_ts).map_err(|_| anyhow::anyhow!("cluster timestamp does not fit in i64"))?;
                let abs_ms_i64 = cluster_ts_i64
                    .checked_add(i64::from(block_ts))
                    .ok_or_else(|| anyhow::anyhow!("block timestamp underflow/overflow"))?;
                let abs_ms: u64 = abs_ms_i64
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("block absolute timestamp is negative: {abs_ms_i64}"))?;

                frames.push(FrameAt {
                    abs_ms,
                    is_key_frame: is_kf,
                    data: frame,
                });

                if end_ms <= abs_ms {
                    break;
                }
            }
            Ok(other) => {
                if !in_cluster {
                    headers.push(other);
                }
            }
            Err(TagIteratorError::UnexpectedEOF { .. }) => break,
            Err(e) => return Err(e.into()),
        }
    }

    let cfg = parse_vpx_config_from_headers(&headers)?;
    Ok((cfg, frames))
}

pub(crate) fn find_cut_indices(frames: &[FrameAt], cut_at_ms: u64) -> anyhow::Result<(usize, usize)> {
    let t20_idx = frames
        .iter()
        .position(|f| f.abs_ms >= cut_at_ms)
        .ok_or_else(|| anyhow::anyhow!("no frame at/after cut_at_ms={cut_at_ms}"))?;

    let key_idx = (0..=t20_idx)
        .rev()
        .find(|&i| frames[i].is_key_frame)
        .ok_or_else(|| anyhow::anyhow!("no keyframe found at/before cut point"))?;

    Ok((key_idx, t20_idx))
}
