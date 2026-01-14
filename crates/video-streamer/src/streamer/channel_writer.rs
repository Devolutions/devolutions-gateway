use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{debug, trace};

#[derive(Debug)]
pub(crate) enum ChannelWriterError {
    ChannelClosed,
}

impl std::fmt::Display for ChannelWriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel writer error")
    }
}

impl std::error::Error for ChannelWriterError {}

pub(crate) struct ChannelWriter {
    writer: tokio::sync::mpsc::Sender<Vec<u8>>,
    writes_count: AtomicU64,
    total_bytes_written: AtomicU64,
}

impl ChannelWriter {
    pub(crate) fn new() -> (Self, ChannelWriterReceiver) {
        trace!("ChannelWriter::new - creating channel with capacity 10");
        let (sender, receiver) = tokio::sync::mpsc::channel(10);
        (
            Self {
                writer: sender,
                writes_count: AtomicU64::new(0),
                total_bytes_written: AtomicU64::new(0),
            },
            ChannelWriterReceiver {
                receiver,
                reads_count: AtomicU64::new(0),
                total_bytes_read: AtomicU64::new(0),
            },
        )
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let buf_len = buf.len();
        let write_num = self.writes_count.fetch_add(1, Ordering::Relaxed) + 1;

        trace!(
            write_num,
            buf_len,
            "ChannelWriter::write - sending to channel"
        );

        self.writer
            .blocking_send(buf.to_vec())
            .map_err(|_| {
                let total_bytes = self.total_bytes_written.load(Ordering::Relaxed);
                debug!(
                    write_num,
                    total_bytes,
                    buf_len,
                    "ChannelWriter::write failed - channel closed"
                );
                io::Error::other(ChannelWriterError::ChannelClosed)
            })?;

        let total = self.total_bytes_written.fetch_add(buf_len as u64, Ordering::Relaxed) + buf_len as u64;
        trace!(
            write_num,
            buf_len,
            total_bytes_written = total,
            "ChannelWriter::write completed"
        );

        Ok(buf_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        trace!("ChannelWriter::flush called (no-op)");
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ChannelWriterReceiver {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reads_count: AtomicU64,
    total_bytes_read: AtomicU64,
}

impl ChannelWriterReceiver {
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        let read_num = self.reads_count.fetch_add(1, Ordering::Relaxed) + 1;
        trace!(
            read_num,
            "ChannelWriterReceiver::recv - waiting for data"
        );

        let result = self.receiver.recv().await;

        match &result {
            Some(data) => {
                let data_len = data.len();
                let total = self.total_bytes_read.fetch_add(data_len as u64, Ordering::Relaxed) + data_len as u64;
                trace!(
                    read_num,
                    data_len,
                    total_bytes_read = total,
                    "ChannelWriterReceiver::recv - received data"
                );
            }
            None => {
                let total = self.total_bytes_read.load(Ordering::Relaxed);
                trace!(
                    read_num,
                    total_bytes_read = total,
                    "ChannelWriterReceiver::recv - channel closed (None)"
                );
            }
        }

        result
    }
}
