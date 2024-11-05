use std::sync::Mutex;

use anyhow::Context;
use webm_iterable::{
    matroska_spec::{Master, MatroskaSpec},
    WebmWriter, WriteOptions,
};

use crate::debug::mastroka_spec_name;

pub enum WriteResult {
    Written,
    Buffered,
}

pub struct ControlledTagWriter<T>
where
    T: std::io::Write,
{
    writer: WebmWriter<T>,
    time_offset: Mutex<Option<u64>>,
    cluster_buffer: Vec<MatroskaSpec>,
}

impl<T> ControlledTagWriter<T>
where
    T: std::io::Write,
{
    pub fn new(writer: T) -> Self {
        Self {
            writer: WebmWriter::new(writer),
            time_offset: Mutex::new(None),
            cluster_buffer: Vec::new(),
        }
    }

    /// We expect the incoming tags goes in the following order:
    /// EMBL header -> Segment(Master::Start) -> Tracks -> Cluster(Master::Start) -> Timestamp -> Blocks (SimpleBlock or Block) -> Cluster(Master::End)
    ///                                                            ↑                                         ↓ (cluster start)        ↓
    ///                                                            ↑-----------------------------------------↲------------------------↲
    /// This function will write the incoming tags to achieve the following:
    /// 1. The Timestamp tag is adjusted with the time_offset, which is the first Timestamp tag value
    /// 2. We make sure when Cluster(Master::Start) is received with another Cluster(Master::Start) in the buffer, we clear the buffer (i.e) enforce the order
    /// 3. We make sure to write Segment(Master::Start) with unknown size, since this is streamed data
    ///
    #[instrument(skip(self, tag), level = "debug")]
    pub fn write(&mut self, tag: &MatroskaSpec) -> anyhow::Result<WriteResult> {
        let have_cluster_start_at_0 = self
            .cluster_buffer
            .first()
            .map_or(false, |t| matches!(t, MatroskaSpec::Cluster(Master::Start)));
        let incoming_tag_is_cluster_end = matches!(tag, MatroskaSpec::Cluster(Master::End));
        let cluster_buffer_is_empty = self.cluster_buffer.is_empty();
        let incoming_tag_is_cluster_start = matches!(tag, MatroskaSpec::Cluster(Master::Start));
        let incoming_tag_is_segment_start = matches!(tag, MatroskaSpec::Segment(Master::Start));

        let tag_name = mastroka_spec_name(tag);

        // Keeping the cluster buffer in order.
        if incoming_tag_is_cluster_start && have_cluster_start_at_0 {
            debug!(
                ?tag_name,
                "Current tag is Cluster start and cluster buffer is not empty, clearing buffer"
            );
            self.cluster_buffer.clear();
        }

        // Handle the Timestamp tag with offset adjustment.
        if let MatroskaSpec::Timestamp(timestamp) = *tag {
            let mut time_offset = self.time_offset.lock().unwrap_or_else(|e| e.into_inner());
            let time_offset = *time_offset.get_or_insert(timestamp);

            let adjusted_timestamp = timestamp.saturating_sub(time_offset);

            let updated_tag = MatroskaSpec::Timestamp(adjusted_timestamp);

            self.cluster_buffer.push(updated_tag);

            debug!(
                timestamp = timestamp,
                adjusted_timestamp = adjusted_timestamp,
                time_offset = time_offset,
                "Adjusted Timestamp"
            );

            return Ok(WriteResult::Buffered);
        }

        if have_cluster_start_at_0 && incoming_tag_is_cluster_end {
            debug!(
                ?tag_name,
                "Current tag is Cluster end and cluster buffer is not empty, writing buffer"
            );
            self.cluster_buffer.push(tag.clone());
            for buffered_tag in self.cluster_buffer.drain(..) {
                self.writer
                    .write(&buffered_tag)
                    .with_context(|| format!("failed to write buffered tag: {}", mastroka_spec_name(&buffered_tag)))?;
            }

            return Ok(WriteResult::Written);
        }

        if cluster_buffer_is_empty && incoming_tag_is_cluster_start {
            debug!(
                ?tag_name,
                "Current tag is Cluster start and cluster buffer is empty, writing tag"
            );
            self.cluster_buffer.push(tag.clone());
            return Ok(WriteResult::Buffered);
        }

        if have_cluster_start_at_0 && !incoming_tag_is_cluster_end {
            self.cluster_buffer.push(tag.clone());
            return Ok(WriteResult::Buffered);
        }

        if incoming_tag_is_segment_start {
            debug!("Writing unknown-sized Segment start tag");
            self.writer
                .write_advanced(tag, WriteOptions::is_unknown_sized_element())?;

            return Ok(WriteResult::Written);
        }

        debug!(?tag_name, "Writing tag");
        self.writer
            .write(tag)
            .with_context(|| format!("failed to write tag: {}", tag_name))?;

        Ok(WriteResult::Written)
    }
}
