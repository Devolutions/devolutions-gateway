use std::io;


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
}

impl ChannelWriter {
    pub(crate) fn new() -> (Self, ChannelWriterReceiver) {
        let (sender, receiver) = tokio::sync::mpsc::channel(10);
        (Self { writer: sender }, ChannelWriterReceiver { receiver })
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer
            .blocking_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, ChannelWriterError::ChannelClosed))?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ChannelWriterReceiver {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl ChannelWriterReceiver {
    pub(crate) async fn recv(&mut self) -> Result<Option<Vec<u8>>, ChannelWriterError> {
        Ok(self.receiver.recv().await)
    }
}
