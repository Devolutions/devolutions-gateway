use std::io;
#[cfg(feature = "perf-diagnostics")]
use std::sync::atomic::{AtomicU64, Ordering};

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
    #[cfg(feature = "perf-diagnostics")]
    writes_count: AtomicU64,
    #[cfg(feature = "perf-diagnostics")]
    total_bytes_written: AtomicU64,
}

impl ChannelWriter {
    pub(crate) fn new() -> (Self, ChannelWriterReceiver) {
        perf_trace!("ChannelWriter::new - creating channel with capacity 10");
        let (sender, receiver) = tokio::sync::mpsc::channel(10);
        (
            Self {
                writer: sender,
                #[cfg(feature = "perf-diagnostics")]
                writes_count: AtomicU64::new(0),
                #[cfg(feature = "perf-diagnostics")]
                total_bytes_written: AtomicU64::new(0),
            },
            ChannelWriterReceiver {
                receiver,
                #[cfg(feature = "perf-diagnostics")]
                reads_count: AtomicU64::new(0),
                #[cfg(feature = "perf-diagnostics")]
                total_bytes_read: AtomicU64::new(0),
            },
        )
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let buf_len = buf.len();
        #[cfg(feature = "perf-diagnostics")]
        {
            let write_num = self.writes_count.fetch_add(1, Ordering::Relaxed) + 1;
            perf_trace!(write_num, buf_len, "ChannelWriter::write - sending to channel");
        }

        self.writer.blocking_send(buf.to_vec()).map_err(|_| {
            #[cfg(feature = "perf-diagnostics")]
            {
                let total_bytes = self.total_bytes_written.load(Ordering::Relaxed);
                perf_debug!(
                    write_num = self.writes_count.load(Ordering::Relaxed),
                    total_bytes,
                    buf_len,
                    "ChannelWriter::write failed - channel closed"
                );
            }
            io::Error::other(ChannelWriterError::ChannelClosed)
        })?;

        #[cfg(feature = "perf-diagnostics")]
        {
            let total = self.total_bytes_written.fetch_add(buf_len as u64, Ordering::Relaxed) + buf_len as u64;
            perf_trace!(
                write_num = self.writes_count.load(Ordering::Relaxed),
                buf_len,
                total_bytes_written = total,
                "ChannelWriter::write completed"
            );
        }

        Ok(buf_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        perf_trace!("ChannelWriter::flush called (no-op)");
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ChannelWriterReceiver {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    #[cfg(feature = "perf-diagnostics")]
    reads_count: AtomicU64,
    #[cfg(feature = "perf-diagnostics")]
    total_bytes_read: AtomicU64,
}

impl ChannelWriterReceiver {
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        #[cfg(feature = "perf-diagnostics")]
        {
            let read_num = self.reads_count.fetch_add(1, Ordering::Relaxed) + 1;
            perf_trace!(read_num, "ChannelWriterReceiver::recv - waiting for data");
        }

        let result = self.receiver.recv().await;

        #[cfg(feature = "perf-diagnostics")]
        {
            let read_num = self.reads_count.load(Ordering::Relaxed);
            match &result {
                Some(data) => {
                    let data_len = data.len();
                    let total = self.total_bytes_read.fetch_add(data_len as u64, Ordering::Relaxed) + data_len as u64;
                    perf_trace!(
                        read_num,
                        data_len,
                        total_bytes_read = total,
                        "ChannelWriterReceiver::recv - received data"
                    );
                }
                None => {
                    let total = self.total_bytes_read.load(Ordering::Relaxed);
                    perf_trace!(
                        read_num,
                        total_bytes_read = total,
                        "ChannelWriterReceiver::recv - channel closed (None)"
                    );
                }
            }
        }

        result
    }
}
