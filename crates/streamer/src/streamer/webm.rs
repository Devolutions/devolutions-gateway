use std::io::Seek;

use anyhow::Context;
use tracing::{debug, trace};
use webm_iterable::{
    errors::TagIteratorError,
    matroska_spec::{Master, MatroskaSpec},
    WebmIterator,
};

use crate::reopenable::Reopenable;

pub struct WebmPostionedIterator<R: std::io::Read + Seek + Reopenable> {
    inner: Option<WebmIterator<R>>,
    // The absolute position of the last tag emitted
    last_tag_position: usize,
    // The absolute position of the last cluster start tag emitted
    last_cluster_position: Option<usize>,
    // The absolute position of the last tag emitted before rollback
    rollback_record: Option<usize>,
}

impl<R> WebmPostionedIterator<R>
where
    R: std::io::Read + Seek + Reopenable,
{
    pub fn new(inner: WebmIterator<R>) -> Self {
        Self {
            inner: Some(inner),
            last_tag_position: 0,
            last_cluster_position: None,
            rollback_record: None,
        }
    }

    pub fn next(&mut self) -> Option<Result<MatroskaSpec, TagIteratorError>> {
        let inner = self.inner.as_mut()?;
        let result = inner.next();

        if let Some(Ok(tag)) = &result {
            let record = self.rollback_record.unwrap_or(0);
            // The last emitted tag is relative, i.e when roll back, the last_emitted_tag_offset() will be reset to 0
            self.last_tag_position = record + inner.last_emitted_tag_offset();
            // we check if the tag is BlockGroup Full, because the full element offset will skip the 3 bytes of header
            if matches!(tag, MatroskaSpec::BlockGroup(Master::Full(_))) {
                self.last_tag_position -= 3;
            }
        }

        if let Some(Ok(MatroskaSpec::Cluster(Master::Start))) = &result {
            self.last_cluster_position = Some(self.last_tag_position);
        }

        trace!(position = self.last_tag_position, "Next tag");
        result
    }

    pub fn rollback_to_last_successful_tag(&mut self) -> anyhow::Result<()> {
        debug!(postion = self.last_tag_position, "Rolling back to last successful tag");
        let inner = self.inner.take().ok_or_else(|| anyhow::anyhow!("No inner iterator"))?;
        let mut file = inner.into_inner();
        file.reopen()?;
        file.seek(std::io::SeekFrom::Start(self.last_tag_position as u64))?;
        self.inner = Some(WebmIterator::new(file, &[MatroskaSpec::BlockGroup(Master::Start)]));
        self.rollback_record = Some(self.last_tag_position);

        // what if the last tag is a cluster start tag?
        Ok(())
    }

    pub fn skip(&mut self, number: u32) -> anyhow::Result<()> {
        for _ in 0..number {
            let _ = self.next().context("Failed to skip tag")?;
        }

        Ok(())
    }

    pub fn rollback_to_last_cluster_start(&mut self) -> anyhow::Result<()> {
        let last_cluster_position = self
            .last_cluster_position
            .ok_or_else(|| anyhow::anyhow!("No last cluster position"))?;
        let inner = self.inner.take().ok_or_else(|| anyhow::anyhow!("No inner iterator"))?;
        let mut file = inner.into_inner();
        file.reopen()?;
        file.seek(std::io::SeekFrom::Start(last_cluster_position as u64))?;
        self.inner = Some(WebmIterator::new(file, &[MatroskaSpec::BlockGroup(Master::Start)]));
        self.rollback_record = Some(last_cluster_position);
        self.last_tag_position = last_cluster_position;
        Ok(())
    }

    pub fn last_emitted_tag_offset(&self) -> usize {
        self.inner.as_ref().unwrap().last_emitted_tag_offset()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{debug::mastroka_spec_name, ReOpenableFile};

    use super::*;

    #[test]
    fn test_webm_positioned_iterator_next() {
        let path = Path::new("C:/Users/jou/code/cadeau/media/clock-cut.webm");
        let file = ReOpenableFile::open(path).unwrap();
        let webm_iterator = WebmIterator::new(file, &[MatroskaSpec::BlockGroup(Master::Start)]);
        let mut positioned_iterator = WebmPostionedIterator::new(webm_iterator);

        let _ = positioned_iterator.next().unwrap().unwrap();
        let tag2 = positioned_iterator.next().unwrap().unwrap();
        positioned_iterator.rollback_to_last_successful_tag().unwrap();
        let tag2_again = positioned_iterator.next().unwrap().unwrap();

        let tag_2_name = mastroka_spec_name(&tag2);
        let tag_2_again_name = mastroka_spec_name(&tag2_again);
        assert_eq!(tag_2_name, tag_2_again_name);
    }

    #[test]
    fn test_webm_positioned_iterator_rollback_to_last_cluster_start() {
        let path = Path::new("C:/Users/jou/code/cadeau/media/clock-cut.webm");
        let file = ReOpenableFile::open(path).unwrap();
        let webm_iterator = WebmIterator::new(file, &[MatroskaSpec::BlockGroup(Master::Start)]);
        let mut positioned_iterator = WebmPostionedIterator::new(webm_iterator);

        while let Some(Ok(tag)) = positioned_iterator.next() {
            if let MatroskaSpec::Cluster(Master::Start) = tag {
                break;
            }
        }

        let _ = positioned_iterator.next().unwrap().unwrap();
        let _ = positioned_iterator.next().unwrap().unwrap();

        positioned_iterator.rollback_to_last_cluster_start().unwrap();
        let cluster = positioned_iterator.next().unwrap().unwrap();

        assert!(matches!(cluster, MatroskaSpec::Cluster(Master::Start)));
    }

    #[test]
    fn test_webm_positioned_iterator_rollback_to_last_blockgroup() {
        let path = Path::new("C:/Users/jou/code/cadeau/media/clock.webm");
        let file = ReOpenableFile::open(path).unwrap();
        let webm_iterator = WebmIterator::new(file, &[MatroskaSpec::BlockGroup(Master::Start)]);
        let mut positioned_iterator = WebmPostionedIterator::new(webm_iterator);

        while let Some(Ok(tag)) = positioned_iterator.next() {
            if let MatroskaSpec::Cluster(Master::Start) = tag {
                break;
            }
        }

        let _ = positioned_iterator.next().unwrap().unwrap();
        let _ = positioned_iterator.next().unwrap().unwrap();

        positioned_iterator.rollback_to_last_successful_tag().unwrap();
        let block_group = positioned_iterator.next().unwrap().unwrap();
        assert!(matches!(block_group, MatroskaSpec::BlockGroup(Master::Full(_))));
    }
}
