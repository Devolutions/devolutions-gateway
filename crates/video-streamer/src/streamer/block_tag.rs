use std::fmt;

use anyhow::Context;
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
    pub(crate) fn new(tag: MatroskaSpec, cluster_timestamp: Option<u64>) -> anyhow::Result<Self> {
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
                let is_key_frame = block.read_frame_data()?.iter().any(|frame| is_key_frame(frame.data));

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

fn is_key_frame(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }
    buffer[0] & 0x1 == 0
}
