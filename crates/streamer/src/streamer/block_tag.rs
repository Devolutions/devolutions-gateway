use std::num::TryFromIntError;

use anyhow::Context;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

#[derive(Clone)]
pub enum BlockTag<'a> {
    SimpleBlock(&'a [u8]),
    BlockGroup(&'a [MatroskaSpec]),
}

#[derive(Clone)]
pub struct VideoBlock<'a> {
    pub(crate) cluster_timestamp: u64,
    pub(crate) timestamp: i16,
    pub(crate) is_key_frame: bool,
    pub(crate) block_tag: BlockTag<'a>,
}

impl<'a> VideoBlock<'a> {
    pub fn new(tag: &'a MatroskaSpec, cluster_timestamp: u64) -> anyhow::Result<Self> {
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
                    .context("Block not found inside block group")?;

                let block = Block::try_from(block)?;
                let timestamp = block.timestamp;
                let is_key_frame = block.read_frame_data()?.iter().any(|frame| is_key_frame(frame.data));

                Self {
                    cluster_timestamp,
                    block_tag: BlockTag::BlockGroup(children),
                    timestamp,
                    is_key_frame,
                }
            }
            MatroskaSpec::SimpleBlock(data) => {
                let simple_block = SimpleBlock::try_from(data)?;
                Self {
                    cluster_timestamp,
                    timestamp: simple_block.timestamp,
                    is_key_frame: simple_block.keyframe,
                    block_tag: BlockTag::SimpleBlock(data),
                }
            }
            _ => anyhow::bail!("BlockGroup expected, got {:?}", tag),
        };

        Ok(result)
    }

    pub fn absolute_timestamp(&self) -> Result<u64, TryFromIntError> {
        let timestamp = u64::try_from(self.timestamp)?;
        Ok(self.cluster_timestamp + timestamp)
    }

    // We only handle non-lacing frames for now
    pub fn get_frame(&self) -> anyhow::Result<Vec<u8>> {
        let frame: Vec<_> = match self.block_tag {
            BlockTag::SimpleBlock(data) => {
                let simple_block = SimpleBlock::try_from(data).unwrap();
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
                    .context("Block not found inside block group")?;

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

fn is_key_frame(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }
    buffer[0] & 0x1 == 0
}