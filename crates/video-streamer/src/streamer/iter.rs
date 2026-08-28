use std::io::{Read, Seek, SeekFrom};

use bytes::BytesMut;
use cadeau::xmf::vpx::VpxCodec;
use ebml_iterable::TagDecoder;
use thiserror::Error;
use webm_iterable::errors::TagIteratorError;
use webm_iterable::matroska_spec::{Block, Master, MatroskaSpec, SimpleBlock};

use super::block_tag::is_vpx_key_frame;
use crate::reopenable::Reopenable;

const INPUT_CHUNK_SIZE: usize = 8 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) enum LastKeyFrameInfo {
    NotMet { cluster_timestamp: Option<u64> },
    Met { position: usize, cluster_timestamp: u64 },
}

pub(crate) struct WebmPositionedIterator<R: Read + Seek + Reopenable> {
    reader: R,
    decoder: TagDecoder<MatroskaSpec>,
    input: BytesMut,
    previous_emitted_tag_postion: usize,
    last_key_frame_info: LastKeyFrameInfo,
    // File offset of decoder position 0 after the last seek.
    rollback_record: Option<usize>,
    codec: VpxCodec,
}

#[derive(Debug, Error)]
pub(crate) enum IteratorError {
    #[error("Inner Iterator Error: {0}")]
    InnerError(#[from] TagIteratorError),
    #[error("Value Expected: {0}")]
    ValueExpected(&'static str),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Webm Coercion Error: {0}")]
    WebmCoercionError(#[from] webm_iterable::errors::WebmCoercionError),
}

impl<R> WebmPositionedIterator<R>
where
    R: Read + Seek + Reopenable,
{
    pub(crate) fn new(reader: R, codec: VpxCodec) -> Self {
        Self {
            reader,
            decoder: new_decoder(),
            input: BytesMut::new(),
            previous_emitted_tag_postion: 0,
            rollback_record: None,
            last_key_frame_info: LastKeyFrameInfo::NotMet {
                cluster_timestamp: None,
            },
            codec,
        }
    }

    pub(crate) fn set_codec(&mut self, codec: VpxCodec) {
        self.codec = codec;
    }

    pub(crate) fn next(&mut self) -> Option<Result<MatroskaSpec, IteratorError>> {
        loop {
            match self.decoder.decode(&mut self.input) {
                Ok(Some(positioned)) => {
                    return Some(self.observe_tag(positioned.tag, positioned.offset));
                }
                Ok(None) => match self.fill_input() {
                    Ok(0) => return None,
                    Ok(_) => continue,
                    Err(error) => return Some(Err(error.into())),
                },
                Err(error) => return Some(Err(error.into())),
            }
        }
    }

    pub(crate) fn refresh_from_disk(&mut self) -> anyhow::Result<()> {
        self.reader.reopen()?;
        let absolute_read_head = self.rollback_record.unwrap_or(0) + self.decoder.position() + self.input.len();
        self.reader.seek(SeekFrom::Start(absolute_read_head.try_into()?))?;
        Ok(())
    }

    pub(crate) fn rollback_to_last_key_frame(&mut self) -> Result<LastKeyFrameInfo, IteratorError> {
        let LastKeyFrameInfo::Met {
            position: last_key_frame_position,
            ..
        } = self.last_key_frame_info
        else {
            return Ok(self.last_key_frame_info);
        };

        self.reader.reopen()?;
        self.reader.seek(SeekFrom::Start(last_key_frame_position as u64))?;
        self.decoder = new_decoder();
        self.input.clear();
        self.rollback_record = Some(last_key_frame_position);
        self.previous_emitted_tag_postion = last_key_frame_position;
        Ok(self.last_key_frame_info)
    }

    pub(crate) fn previous_emitted_tag_postion(&self) -> usize {
        self.previous_emitted_tag_postion
    }

    fn fill_input(&mut self) -> std::io::Result<usize> {
        let mut buf = [0u8; INPUT_CHUNK_SIZE];
        let read = self.reader.read(&mut buf)?;
        if read > 0 {
            self.input.extend_from_slice(&buf[..read]);
        }
        Ok(read)
    }

    fn observe_tag(&mut self, tag: MatroskaSpec, relative_offset: usize) -> Result<MatroskaSpec, IteratorError> {
        let record = self.rollback_record.unwrap_or(0);
        let absolute_offset = record + relative_offset;
        if absolute_offset >= self.previous_emitted_tag_postion {
            self.previous_emitted_tag_postion = absolute_offset;
        }

        if let MatroskaSpec::Timestamp(time) = tag {
            match self.last_key_frame_info {
                LastKeyFrameInfo::NotMet {
                    cluster_timestamp: ref mut potential_cluster_timestamp,
                    ..
                } => {
                    potential_cluster_timestamp.replace(time);
                }
                LastKeyFrameInfo::Met {
                    ref mut cluster_timestamp,
                    ..
                } => {
                    *cluster_timestamp = time;
                }
            }
            return Ok(tag);
        }

        match self.is_key_frame(&tag) {
            Err(error) => return Err(error),
            Ok(false) => {}
            Ok(true) => {
                perf_trace!(
                    last_tag_position = self.previous_emitted_tag_postion,
                    last_key_frame_info = ?self.last_key_frame_info,
                    "Key Frame Found"
                );
                match self.last_key_frame_info {
                    LastKeyFrameInfo::NotMet { cluster_timestamp } => {
                        let Some(cluster_timestamp) = cluster_timestamp else {
                            return Err(IteratorError::ValueExpected("cluster_timestamp"));
                        };
                        self.last_key_frame_info = LastKeyFrameInfo::Met {
                            position: self.previous_emitted_tag_postion,
                            cluster_timestamp,
                        };
                    }
                    LastKeyFrameInfo::Met { ref mut position, .. } => {
                        *position = self.previous_emitted_tag_postion;
                    }
                }
            }
        }

        Ok(tag)
    }

    fn is_key_frame(&self, tag: &MatroskaSpec) -> Result<bool, IteratorError> {
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

                Ok(frame.into_iter().any(|frame| is_vpx_key_frame(frame.data, self.codec)))
            }
            MatroskaSpec::SimpleBlock(data) => {
                let simple_block = SimpleBlock::try_from(data)?;
                Ok(simple_block.keyframe)
            }
            _ => Ok(false),
        }
    }
}

fn new_decoder() -> TagDecoder<MatroskaSpec> {
    TagDecoder::new(&[MatroskaSpec::BlockGroup(Master::Start)])
}

#[cfg(test)]
mod tests {
    use std::io::{self, SeekFrom};

    use webm_iterable::{WebmWriter, WriteOptions};

    use super::*;

    struct GrowingFile {
        data: Vec<u8>,
        pos: usize,
        visible: usize,
    }

    impl Read for GrowingFile {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.visible {
                return Ok(0);
            }
            let read = (self.visible - self.pos).min(buf.len());
            buf[..read].copy_from_slice(&self.data[self.pos..self.pos + read]);
            self.pos += read;
            Ok(read)
        }
    }

    impl Seek for GrowingFile {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            let next = match from {
                SeekFrom::Start(offset) => i64::try_from(offset).map_err(io::Error::other)?,
                SeekFrom::Current(offset) => i64::try_from(self.pos)
                    .map_err(io::Error::other)?
                    .checked_add(offset)
                    .ok_or_else(|| io::Error::other("seek overflow"))?,
                SeekFrom::End(offset) => i64::try_from(self.visible)
                    .map_err(io::Error::other)?
                    .checked_add(offset)
                    .ok_or_else(|| io::Error::other("seek overflow"))?,
            };
            if next < 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
            }
            self.pos = usize::try_from(next).map_err(io::Error::other)?;
            Ok(self.pos as u64)
        }
    }

    impl Reopenable for GrowingFile {
        fn reopen(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn sample_webm() -> Vec<u8> {
        let mut dest = Vec::new();
        let mut writer = WebmWriter::new(&mut dest);
        writer
            .write(&MatroskaSpec::Ebml(Master::Start))
            .expect("write ebml start");
        writer.write(&MatroskaSpec::EbmlVersion(1)).expect("write ebml version");
        writer.write(&MatroskaSpec::Ebml(Master::End)).expect("write ebml end");
        writer
            .write_advanced(
                &MatroskaSpec::Segment(Master::Start),
                WriteOptions::is_unknown_sized_element(),
            )
            .expect("write segment start");
        writer
            .write(&MatroskaSpec::Cluster(Master::Start))
            .expect("write cluster start");
        writer.write(&MatroskaSpec::Timestamp(0)).expect("write timestamp");
        writer.flush().expect("flush webm writer");
        dest
    }

    #[test]
    fn incomplete_input_waits_then_resumes_after_refresh() {
        let data = sample_webm();
        assert!(
            data.len() > 16,
            "fixture too small ({} bytes): {:02x?}",
            data.len(),
            data
        );

        let mut complete = WebmPositionedIterator::new(
            GrowingFile {
                data: data.clone(),
                pos: 0,
                visible: data.len(),
            },
            VpxCodec::VP8,
        );
        let complete_tags = std::iter::from_fn(|| complete.next())
            .map(|tag| tag.expect("complete fixture should parse"))
            .collect::<Vec<_>>();
        assert!(
            complete_tags
                .iter()
                .any(|tag| matches!(tag, MatroskaSpec::Cluster(Master::Start))),
            "complete fixture tags: {complete_tags:?}"
        );

        let mut iter = WebmPositionedIterator::new(
            GrowingFile {
                data: data.clone(),
                pos: 0,
                visible: 4,
            },
            VpxCodec::VP8,
        );

        assert!(iter.next().is_none());

        iter.reader.visible = data.len();
        iter.refresh_from_disk().expect("refresh growing file");

        let mut saw_cluster = false;
        while let Some(tag) = iter.next() {
            if matches!(tag.expect("valid tag"), MatroskaSpec::Cluster(Master::Start)) {
                saw_cluster = true;
                break;
            }
        }
        assert!(saw_cluster);
    }
}
