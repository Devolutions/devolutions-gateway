use std::fmt;

use anyhow::Context;
use cadeau::xmf::vpx::VpxCodec;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

#[derive(Clone)]
pub(crate) enum BlockTag {
    SimpleBlock(Vec<u8>),
    BlockGroup(Vec<MatroskaSpec>),
}

#[derive(Clone)]
pub(crate) struct VideoBlock {
    pub(crate) cluster_timestamp: Option<u64>,
    pub(crate) timestamp: i16,
    pub(crate) is_key_frame: bool,
    pub(crate) block_tag: BlockTag,
}

impl fmt::Debug for VideoBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoBlock")
            .field("cluster_timestamp", &self.cluster_timestamp)
            .field("timestamp", &self.timestamp)
            .field("is_key_frame", &self.is_key_frame)
            .field(
                "block_tag",
                &match self.block_tag {
                    BlockTag::SimpleBlock(_) => "SimpleBlock",
                    BlockTag::BlockGroup(_) => "BlockGroup",
                },
            )
            .finish()
    }
}

impl VideoBlock {
    pub(crate) fn new(tag: MatroskaSpec, cluster_timestamp: Option<u64>, codec: VpxCodec) -> anyhow::Result<Self> {
        let result = match tag {
            MatroskaSpec::BlockGroup(Master::Full(children)) => {
                let block = children
                    .iter()
                    .find_map(|tag| {
                        if let MatroskaSpec::Block(block) = tag {
                            Some(block)
                        } else {
                            None
                        }
                    })
                    .context("MatroskaSpec::Block not found inside block group")?;

                let block = Block::try_from(block)?;
                let timestamp = block.timestamp;
                let is_key_frame = block
                    .read_frame_data()?
                    .iter()
                    .any(|frame| is_vpx_key_frame(frame.data, codec));

                Self {
                    cluster_timestamp,
                    block_tag: BlockTag::BlockGroup(children),
                    timestamp,
                    is_key_frame,
                }
            }
            MatroskaSpec::SimpleBlock(data) => {
                let simple_block = SimpleBlock::try_from(&data)?;
                Self {
                    cluster_timestamp,
                    timestamp: simple_block.timestamp,
                    is_key_frame: simple_block.keyframe,
                    block_tag: BlockTag::SimpleBlock(data),
                }
            }
            _ => anyhow::bail!("blockGroup expected, got {:?}", tag),
        };

        Ok(result)
    }

    pub(crate) fn absolute_timestamp(&self) -> anyhow::Result<u64> {
        let timestamp = u64::try_from(self.timestamp)?;
        Ok(self
            .cluster_timestamp
            .with_context(|| format!("Cluster timestamp not found for timestamp: {}", self.timestamp))?
            + timestamp)
    }

    // We only handle non-lacing frames for now
    pub(crate) fn get_frame(&self) -> anyhow::Result<Vec<u8>> {
        let frame: Vec<_> = match &self.block_tag {
            BlockTag::SimpleBlock(data) => {
                let simple_block = SimpleBlock::try_from(data)?;
                simple_block
                    .read_frame_data()?
                    .into_iter()
                    .map(|frame| frame.data.to_owned())
                    .collect()
            }
            BlockTag::BlockGroup(block_group) => {
                let block = block_group
                    .iter()
                    .find_map(|tag| {
                        if let MatroskaSpec::Block(block) = tag {
                            Some(block)
                        } else {
                            None
                        }
                    })
                    .context("MatroskaSpec::Block not found inside block group")?;

                let block = Block::try_from(block)?;

                block
                    .read_frame_data()?
                    .into_iter()
                    .map(|frame| frame.data.to_owned())
                    .collect()
            }
        };

        assert!(frame.len() == 1);
        Ok(frame[0].clone())
    }
}

pub(crate) fn is_vpx_key_frame(buffer: &[u8], codec: VpxCodec) -> bool {
    match codec {
        VpxCodec::VP8 => is_vp8_key_frame(buffer),
        VpxCodec::VP9 => is_vp9_key_frame(buffer),
    }
}

/// VP8 keyframe detection.
///
/// RFC 6386 Section 9.1 "Uncompressed Data Chunk":
/// https://datatracker.ietf.org/doc/html/rfc6386#section-9.1
///
/// First byte layout (LSB-first bitstream):
///   bit 0: frame_type (0 = key frame, 1 = inter frame)
///   bits 1-2: version
///   bit 3: show_frame
///   bits 4-7: first_part_size (bits 0-3)
///
/// We only need bit 0: `buffer[0] & 0x1 == 0` means keyframe.
fn is_vp8_key_frame(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }
    buffer[0] & 0x1 == 0
}

/// VP9 keyframe detection.
///
/// VP9 Bitstream & Decoding Process Specification v0.6, Section 6.2 "Uncompressed header syntax":
/// https://storage.googleapis.com/downloads.webmproject.org/docs/vp9/vp9-bitstream-specification-v0.6-20160331-draft.pdf
///
/// Unlike VP8 which uses a LSB-first bitstream, VP9 uses a MSB-first bitstream.
/// The first byte layout depends on the profile:
///
/// For profiles 0-2 (first byte, MSB to LSB):
///   bits 7-6: frame_marker (must be 0b10 to identify VP9)
///   bit 5:    profile_low_bit
///   bit 4:    profile_high_bit
///   bit 3:    show_existing_frame (if 1, frame is a reference to an already-decoded frame, not a keyframe)
///   bit 2:    frame_type (0 = KEY_FRAME, 1 = NON_KEY_FRAME)
///   bits 1-0: (remaining header fields)
///
/// For profile 3 (first byte, MSB to LSB):
///   bits 7-6: frame_marker (must be 0b10)
///   bit 5:    profile_low_bit (1)
///   bit 4:    profile_high_bit (1)
///   bit 3:    reserved_zero
///   bit 2:    show_existing_frame
///   bit 1:    frame_type (0 = KEY_FRAME, 1 = NON_KEY_FRAME)
///   bit 0:    (remaining header fields)
///
/// Profile 3 has an extra reserved_zero bit after the profile bits, which shifts
/// show_existing_frame and frame_type one position to the right.
///
/// Note: the profile is encoded with swapped bit order: `profile = (high_bit << 1) | low_bit`,
/// i.e. `profile = (bit4 << 1) | bit5`.
///
/// A frame is a keyframe when: show_existing_frame == 0 AND frame_type == 0.
pub(crate) fn is_vp9_key_frame(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }
    let b0 = buffer[0];

    // Validate frame_marker (bits 7-6) is 0b10
    if (b0 >> 6) != 0b10 {
        return false;
    }

    // profile = (high_bit << 1) | low_bit = (bit4 << 1) | bit5
    let profile = (((b0 >> 4) & 1) << 1) | ((b0 >> 5) & 1);

    if profile == 3 {
        // Profile 3: show_existing_frame is bit 2, frame_type is bit 1
        (b0 & 0x04) == 0 && (b0 & 0x02) == 0
    } else {
        // Profiles 0-2: show_existing_frame is bit 3, frame_type is bit 2
        (b0 & 0x08) == 0 && (b0 & 0x04) == 0
    }
}


#[cfg(test)]
mod tests {
    use super::is_vp9_key_frame;

    #[test]
    fn vp9_empty_buffer_is_not_keyframe() {
        assert!(!is_vp9_key_frame(&[]));
    }

    #[test]
    fn vp9_marker_mismatch_is_not_keyframe() {
        // frame_marker (bits 7-6) != 0b10 → rejected even if other bits look like keyframe.
        // 0x00 → frame_marker = 0b00
        assert!(!is_vp9_key_frame(&[0x00]));
    }

    #[test]
    fn vp9_profiles_0_to_2_keyframe_detected() {
        // Profile 0: frame_marker=0b10, profile_low=0, profile_high=0,
        // show_existing_frame(bit3)=0, frame_type(bit2)=0.
        // 0b1000_0000 = 0x80
        assert!(is_vp9_key_frame(&[0x80]));
    }

    #[test]
    fn vp9_profiles_0_to_2_show_existing_frame_is_not_keyframe() {
        // Profile 0: show_existing_frame(bit3)=1, frame_type(bit2)=0.
        // 0b1000_1000 = 0x88
        assert!(!is_vp9_key_frame(&[0x88]));
    }

    #[test]
    fn vp9_profiles_0_to_2_inter_frame_is_not_keyframe() {
        // Profile 0: show_existing_frame(bit3)=0, frame_type(bit2)=1.
        // 0b1000_0100 = 0x84
        assert!(!is_vp9_key_frame(&[0x84]));
    }

    #[test]
    fn vp9_profile_3_keyframe_detected() {
        // Profile 3: frame_marker=0b10, profile_low(bit5)=1, profile_high(bit4)=1,
        // reserved_zero(bit3)=0, show_existing_frame(bit2)=0, frame_type(bit1)=0.
        // 0b1011_0000 = 0xB0
        assert!(is_vp9_key_frame(&[0xB0]));
    }

    #[test]
    fn vp9_profile_3_show_existing_frame_is_not_keyframe() {
        // Profile 3: show_existing_frame(bit2)=1, frame_type(bit1)=0.
        // 0b1011_0100 = 0xB4
        assert!(!is_vp9_key_frame(&[0xB4]));
    }

    #[test]
    fn vp9_profile_3_inter_frame_is_not_keyframe() {
        // Profile 3: show_existing_frame(bit2)=0, frame_type(bit1)=1.
        // 0b1011_0010 = 0xB2
        assert!(!is_vp9_key_frame(&[0xB2]));
    }
}
