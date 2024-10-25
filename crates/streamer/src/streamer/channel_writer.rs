use std::io;

pub(crate) struct ChannelWriter {
    writer: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ChannelWriter {
    pub(crate) fn new() -> (Self, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(10);
        (Self { writer: sender }, receiver)
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer
            .blocking_send(buf.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to write to channel {:?}", e)))?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
