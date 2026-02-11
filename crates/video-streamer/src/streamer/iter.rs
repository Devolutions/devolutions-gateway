use std::io::Seek;

use anyhow::Context;
use cadeau::xmf::vpx::is_key_frame;
use thiserror::Error;
use webm_iterable::WebmIterator;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

use crate::reopenable::Reopenable;

#[derive(Debug, Clone, Copy)]
pub(crate) enum LastKeyFrameInfo {
    NotMet {
        cluster_start_position: Option<usize>,
        cluster_timestamp: Option<u64>,
    },
    Met {
        position: usize,
        cluster_timestamp: u64,
        cluster_start_position: usize,
    },
}

pub(crate) struct WebmPositionedIterator<R: std::io::Read + Seek + Reopenable> {
    inner: Option<WebmIterator<R>>,
    // The absolute position of the last tag emitted
    previous_emitted_tag_postion: usize,
    // The absolute position of the last cluster start tag emitted
    last_cluster_position: Option<usize>,

    // The absolute position of the last block group/simple block that is a keyframe
    last_key_frame_info: LastKeyFrameInfo,
    // The absolute position of the last tag emitted before rollback
    rollback_record: Option<usize>,

    // When rollback at BlockGroup Full, then the Cluster(Master::end) will not be emitted
    // So we need to keep track of weather we hit the cluster start and rolled back
    // if so, we need to emit the cluster end tag manually
    rolled_back_between_cluster: bool,

    should_emit_cache: Option<MatroskaSpec>,
}

#[derive(Debug, Error)]
pub(crate) enum IteratorError {
    #[error("Inner Iterator Error: {0}")]
    InnerError(#[from] TagIteratorError),
    #[error("Position Correction Error: {before_correct_position}")]
    PositionCorrectionError { before_correct_position: u64 },
    #[error("Value Expected: {0}")]
    ValueExpected(&'static str),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Webm Coercion Error: {0}")]
    WebmCoercionError(#[from] webm_iterable::errors::WebmCoercionError),
}

impl<R> WebmPositionedIterator<R>
where
    R: std::io::Read + Seek + Reopenable,
{
    pub(crate) fn new(mut inner: WebmIterator<R>) -> Self {
        inner.emit_master_end_when_eof(false);
        Self {
            inner: Some(inner),
            previous_emitted_tag_postion: 0,
            last_cluster_position: None,
            rollback_record: None,
            rolled_back_between_cluster: false,
            should_emit_cache: None,
            last_key_frame_info: LastKeyFrameInfo::NotMet {
                cluster_timestamp: None,
                cluster_start_position: None,
            },
        }
    }

    pub(crate) fn next(&mut self) -> Option<Result<MatroskaSpec, IteratorError>> {
        let Some(inner) = self.inner.as_mut() else {
            return Some(Err(IteratorError::ValueExpected("inner tag writer")));
        };

        let result = inner.next();

        if result.is_none() {
            let record = self.rollback_record.unwrap_or(0);
            if record + inner.last_emitted_tag_offset() > self.previous_emitted_tag_postion {
                self.previous_emitted_tag_postion = record + inner.last_emitted_tag_offset();
            }
            return None;
        }

        if let Some(Ok(tag)) = &result {
            let record = self.rollback_record.unwrap_or(0);
            // The last emitted tag is relative, i.e when rollback, the last_emitted_tag_offset() will be reset to 0
            if record + inner.last_emitted_tag_offset() >= self.previous_emitted_tag_postion {
                self.previous_emitted_tag_postion = record + inner.last_emitted_tag_offset();
            }

            if matches!(tag, MatroskaSpec::BlockGroup(Master::Full(_))) {
                // we check if the tag is BlockGroup Full,
                // If so, we need to correct for the last tag position
                // because the full element offset will skip the header

                if let Err(e) =
                    self.correct_for_blockgroup_header()
                        .map_err(|_| IteratorError::PositionCorrectionError {
                            before_correct_position: self.previous_emitted_tag_postion as u64,
                        })
                {
                    return Some(Err(e));
                }
            }

            if let MatroskaSpec::Timestamp(time) = tag {
                match self.last_key_frame_info {
                    LastKeyFrameInfo::NotMet {
                        cluster_timestamp: ref mut potential_cluster_timestamp,
                        ..
                    } => {
                        potential_cluster_timestamp.replace(*time);
                    }
                    LastKeyFrameInfo::Met {
                        ref mut cluster_timestamp,
                        ..
                    } => {
                        *cluster_timestamp = *time;
                    }
                }

                return result.map(|result| result.map_err(|err| err.into()));
            }

            match Self::is_key_frame(tag) {
                Err(e) => {
                    return Some(Err(e));
                }
                Ok(false) => {}
                Ok(true) => {
                    perf_trace!(
                        last_tag_position = self.previous_emitted_tag_postion,
                        last_key_frame_info = ?self.last_key_frame_info,
                        "Key Frame Found"
                    );
                    match self.last_key_frame_info {
                        LastKeyFrameInfo::NotMet {
                            cluster_timestamp,
                            cluster_start_position,
                        } => {
                            let Some(cluster_timestamp) = cluster_timestamp else {
                                return Some(Err(IteratorError::ValueExpected("cluster_timestamp")));
                            };

                            let Some(cluster_start_position) = cluster_start_position else {
                                return Some(Err(IteratorError::ValueExpected("cluster_start_position")));
                            };

                            self.last_key_frame_info = LastKeyFrameInfo::Met {
                                position: self.previous_emitted_tag_postion,
                                cluster_timestamp,
                                cluster_start_position,
                            }
                        }
                        LastKeyFrameInfo::Met { ref mut position, .. } => {
                            *position = self.previous_emitted_tag_postion;
                        }
                    }
                }
            };

            if let Some(Ok(MatroskaSpec::Cluster(Master::Start))) = &result {
                self.last_cluster_position = Some(self.previous_emitted_tag_postion);

                match self.last_key_frame_info {
                    LastKeyFrameInfo::NotMet {
                        ref mut cluster_start_position,
                        ..
                    } => {
                        cluster_start_position.replace(self.previous_emitted_tag_postion);
                    }
                    LastKeyFrameInfo::Met {
                        ref mut cluster_start_position,
                        ..
                    } => {
                        *cluster_start_position = self.previous_emitted_tag_postion;
                    }
                };

                if self.rolled_back_between_cluster {
                    self.should_emit_cache = Some(MatroskaSpec::Cluster(Master::Start));
                    self.rolled_back_between_cluster = false;
                    return Some(Ok(MatroskaSpec::Cluster(Master::End)));
                } else {
                    return result.map(|result| result.map_err(|err| err.into()));
                }
            }
        }

        result.map(|result| result.map_err(|err| err.into()))
    }

    pub(crate) fn rollback_to_last_successful_tag(&mut self) -> anyhow::Result<()> {
        perf_debug!(
            last_tag_position = self.previous_emitted_tag_postion,
            "Rolling back to last successful tag"
        );
        let inner = self.inner.take().context("no inner iterator")?;
        let mut file = inner.into_inner();
        file.reopen()?;
        file.seek(std::io::SeekFrom::Start(self.previous_emitted_tag_postion as u64))?;
        self.new_inner(file);
        self.rollback_record = Some(self.previous_emitted_tag_postion);

        if self
            .last_cluster_position
            .map(|last_cluster_position| last_cluster_position != self.previous_emitted_tag_postion)
            .unwrap_or(false)
        {
            self.rolled_back_between_cluster = true;
        }

        Ok(())
    }

    pub(crate) fn skip(&mut self, number: u32) -> anyhow::Result<()> {
        for _ in 0..number {
            let _ = self.next().context("failed to skip tag")??;
        }

        Ok(())
    }

    pub(crate) fn rollback_to_last_key_frame(&mut self) -> Result<LastKeyFrameInfo, IteratorError> {
        let LastKeyFrameInfo::Met {
            position: last_key_frame_position,
            cluster_start_position,
            ..
        } = self.last_key_frame_info
        else {
            return Ok(self.last_key_frame_info);
        };

        let inner = self
            .inner
            .take()
            .ok_or(IteratorError::ValueExpected("inner tag writer"))?;
        let mut file = inner.into_inner();
        file.reopen()?;
        file.seek(std::io::SeekFrom::Start(last_key_frame_position as u64))?;
        self.rollback_record = Some(last_key_frame_position);
        self.previous_emitted_tag_postion = last_key_frame_position;
        self.new_inner(file);
        self.last_cluster_position = Some(cluster_start_position);
        Ok(self.last_key_frame_info)
    }

    pub(crate) fn previous_emitted_tag_postion(&self) -> usize {
        self.previous_emitted_tag_postion
    }

    // The BlockGroup element binary layout is like this
    // a0 [VInt for content length] [content]
    // We search for a0 [VInt for content length] from 16 bytes backward from current position
    fn correct_for_blockgroup_header(&mut self) -> anyhow::Result<()> {
        let file = self.inner.as_mut().context("inner is none")?.get_mut();
        let current_position = file.stream_position()?;
        file.seek(std::io::SeekFrom::Start(self.previous_emitted_tag_postion.try_into()?))?;
        let mut lookback_range = [0u8; 16];
        file.seek_relative(-16)?;
        file.read_exact(&mut lookback_range)?;

        let mut found = false;
        for i in (1..lookback_range.len()).rev() {
            let slice = &lookback_range[i..];
            if slice[0] == 0xa0 && read_vint(&slice[1..]).is_ok_and(|opt| opt.is_some()) {
                let trace_back_offset = 16 - i;
                self.previous_emitted_tag_postion -= trace_back_offset;
                found = true;
                break;
            }
        }

        file.seek(std::io::SeekFrom::Start(current_position))?;
        if !found {
            anyhow::bail!("no EBML Element of BlockGroup Found");
        }

        Ok(())
    }

    fn is_key_frame(tag: &MatroskaSpec) -> Result<bool, IteratorError> {
        match tag {
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
                    .ok_or(IteratorError::ValueExpected(
                        "MatroskaSpec::Block not found in MatroskaSpec::BlockGroup",
                    ))?;

                let block = Block::try_from(block)?;
                let frame = block.read_frame_data()?;

                Ok(frame.into_iter().any(|frame| is_key_frame(frame.data)))
            }
            MatroskaSpec::SimpleBlock(data) => {
                let simple_block = SimpleBlock::try_from(data)?;
                Ok(simple_block.keyframe)
            }
            _ => Ok(false),
        }
    }

    fn new_inner(&mut self, reader: R) {
        let mut inner = WebmIterator::new(reader, &[MatroskaSpec::BlockGroup(Master::Start)]);
        // Disable automatic Master::End or Master::Start tag emission at EOF.
        //
        // Scenario 1 - EOF within a Cluster:
        // - When we hit EOF between Cluster(Master::Start) and expected Cluster(Master::End)
        // - By default, iterator emits Cluster(Master::End) automatically
        // - This causes last_emitted_tag_offset() to jump back to the Cluster(Master::Start) position
        // - Our position tracking becomes incorrect as it's smaller than BlockGroup/SimpleBlock we read
        //
        // Scenario 2 - EOF when reading from middle of a Cluster:
        // - When we start reading from middle of a Cluster (after rollback/seek)
        // - At EOF, iterator assumes we need a matching Start tag.
        // - It emits a Cluster(Master::Start) with offset 0
        // - This resets last_emitted_tag_offset() to 0, breaking our position tracking
        inner.emit_master_end_when_eof(false);
        self.inner = Some(inner);
    }
}

pub(crate) fn read_vint(buffer: &[u8]) -> anyhow::Result<Option<(u64, usize)>> {
    if buffer.is_empty() {
        return Ok(None);
    }

    if buffer[0] == 0 {
        anyhow::bail!("VInt first byte cannot be 0");
    }

    let length = 8 - buffer[0].ilog2() as usize;

    if length > buffer.len() {
        // Not enough data in the buffer to read out the vint value
        return Ok(None);
    }

    let mut value = u64::from(buffer[0]);
    value -= 1 << (8 - length);

    for item in buffer.iter().take(length).skip(1) {
        value <<= 8;
        value += u64::from(*item);
    }

    Ok(Some((value, length)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_vint() {
        let test_cases = vec![
            (vec![0x46, 0xa0, 0x00], Some((1696, 2))), // Single-byte VINT
            (vec![0x46, 0xa0], Some((1696, 2))),       // Single-byte VINT
        ];

        for (input, expected) in test_cases {
            let result = read_vint(&input);
            let Ok(result) = result else {
                panic!("Failed to read vint");
            };
            assert_eq!(result, expected);
        }
    }
}
