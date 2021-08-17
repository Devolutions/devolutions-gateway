use super::proto::{
    JmuxChannelMessageType, JmuxMsgChannelClose, JmuxMsgChannelData, JmuxMsgChannelEof, JmuxMsgChannelOpen,
    JmuxMsgChannelOpenFailure, JmuxMsgChannelOpenSuccess, JmuxMsgChannelWindowAdjust,
};
use crate::jmux::proto::{CommonDefinitions, Marshall, Unmarshall};
use anyhow::anyhow;
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::Mutex;

#[derive(Debug, PartialEq)]
pub enum JmuxChannelMsg {
    Open(JmuxMsgChannelOpen),
    OpenSuccess(JmuxMsgChannelOpenSuccess),
    OpenFailure(JmuxMsgChannelOpenFailure),
    WindowAdjust(JmuxMsgChannelWindowAdjust),
    Data(JmuxMsgChannelData),
    Eof(JmuxMsgChannelEof),
    Close(JmuxMsgChannelClose),
}

#[derive(Clone)]
pub struct JmuxSender {
    writer: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
}

impl JmuxSender {
    pub fn new(write: Box<dyn AsyncWrite + Unpin + Send>) -> JmuxSender {
        JmuxSender {
            writer: Arc::new(Mutex::new(write)),
        }
    }

    pub async fn send<T: Marshall>(&self, msg: &T) -> Result<(), anyhow::Error> {
        use tokio::io::AsyncWriteExt;

        let packet = msg.marshall();

        let writer = &mut *self.writer.lock().await;
        writer
            .write_all(packet.as_ref())
            .await
            .map_err(|err| anyhow!("Failed write packet to writer:{:?}", err))
    }
}

pub struct JmuxReceiver {
    reader: Arc<Mutex<Box<dyn AsyncRead + Unpin + Send>>>,
}

impl JmuxReceiver {
    pub fn new(reader: Box<dyn AsyncRead + Unpin + Send>) -> JmuxReceiver {
        JmuxReceiver {
            reader: Arc::new(Mutex::new(reader)),
        }
    }

    pub async fn receive(&self) -> Result<JmuxChannelMsg, anyhow::Error> {
        let packet = self
            .read_packet()
            .await
            .map_err(|err| anyhow!("Failed to read packet:{:?}", err))?;

        self.parse_channel_message(packet.as_ref())
    }

    async fn read_packet(&self) -> Result<Vec<u8>, anyhow::Error> {
        let reader = &mut *self.reader.lock().await;

        let msg_type = reader.read_u8().await?;
        let msg_flag = reader.read_u8().await?;
        let msg_size = reader.read_u16().await?;

        let mut packet = vec![msg_type, msg_flag];
        packet.extend_from_slice(&msg_size.to_be_bytes());

        let mut leftover = vec![0u8; msg_size as usize - CommonDefinitions::get_size_of_fixed_part()];
        reader.read_exact(&mut leftover).await?;
        packet.extend_from_slice(leftover.as_slice());

        Ok(packet)
    }

    fn parse_channel_message(&self, packet: &[u8]) -> Result<JmuxChannelMsg, anyhow::Error> {
        let message = match JmuxChannelMessageType::try_from(packet[0])? {
            JmuxChannelMessageType::Open => JmuxChannelMsg::Open(JmuxMsgChannelOpen::unmarshall(packet)?),
            JmuxChannelMessageType::Data => JmuxChannelMsg::Data(JmuxMsgChannelData::unmarshall(packet)?),
            JmuxChannelMessageType::OpenSuccess => {
                JmuxChannelMsg::OpenSuccess(JmuxMsgChannelOpenSuccess::unmarshall(packet)?)
            }
            JmuxChannelMessageType::OpenFailure => {
                JmuxChannelMsg::OpenFailure(JmuxMsgChannelOpenFailure::unmarshall(packet)?)
            }
            JmuxChannelMessageType::WindowAdjust => {
                JmuxChannelMsg::WindowAdjust(JmuxMsgChannelWindowAdjust::unmarshall(packet)?)
            }
            JmuxChannelMessageType::Eof => JmuxChannelMsg::Eof(JmuxMsgChannelEof::unmarshall(packet)?),
            JmuxChannelMessageType::Close => JmuxChannelMsg::Close(JmuxMsgChannelClose::unmarshall(packet)?),
        };

        Ok(message)
    }
}

#[cfg(test)]
pub mod tests {
    use super::{
        CommonDefinitions, JmuxChannelMessageType, JmuxChannelMsg, JmuxMsgChannelOpen, JmuxReceiver, JmuxSender,
        Marshall, Unmarshall,
    };
    use min_max::min;
    use std::cell::RefCell;
    use std::io::Error;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct MockAsyncWriter {
        is_called: Arc<AtomicBool>,
    }

    impl AsyncWrite for MockAsyncWriter {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<Result<usize, Error>> {
            (*self.is_called).store(true, Ordering::Relaxed);
            Poll::Ready(Ok(1))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct TestJmuxMsg {
        is_marsial_mux_called: RefCell<bool>,
    }

    impl Marshall for TestJmuxMsg {
        fn marshall(&self) -> Vec<u8> {
            *self.is_marsial_mux_called.borrow_mut() = true;
            Vec::new()
        }
    }

    impl Unmarshall for TestJmuxMsg {
        fn unmarshall(_buf: &[u8]) -> Result<Self, anyhow::Error>
        where
            Self: Sized,
        {
            Result::Ok(TestJmuxMsg {
                is_marsial_mux_called: RefCell::new(false),
            })
        }

        fn get_size_of_fixed_part() -> usize {
            4
        }
    }

    struct MockAsyncReader {
        raw_msg: Vec<u8>,
    }
    impl AsyncRead for MockAsyncReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if buf.remaining() > 0 {
                let amount = min(buf.remaining(), self.raw_msg.len());
                buf.put_slice(&self.raw_msg[0..amount]);
                self.raw_msg.drain(0..amount);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[tokio::test]
    async fn unmarshaler_is_called_when_send() {
        let writer = MockAsyncWriter {
            is_called: Arc::new(AtomicBool::new(false)),
        };
        let jmux_sender = JmuxSender::new(Box::new(writer));
        let msg_example = TestJmuxMsg {
            is_marsial_mux_called: RefCell::new(false),
        };

        let send_result = jmux_sender.send(&msg_example).await;

        assert!(send_result.is_ok());
        assert!(*msg_example.is_marsial_mux_called.borrow());
    }

    #[tokio::test]
    async fn test_write_called_on_writer_when_send() {
        let is_called = Arc::new(AtomicBool::new(false));
        let writer = MockAsyncWriter {
            is_called: Arc::clone(&is_called),
        };
        let jmux_sender = JmuxSender::new(Box::new(writer));
        let msg_example = JmuxMsgChannelOpen {
            initial_window_size: 1024,
            common_defs: CommonDefinitions {
                msg_size: 36,
                msg_flags: 0,
                msg_type: JmuxChannelMessageType::Open,
            },
            sender_channel_id: 1,
            maximum_packet_size: 1024,
            destination_url: "tcp://google.com:443".to_owned(),
        };

        let send_result = jmux_sender.send(&msg_example).await;

        assert!(send_result.is_ok());
        assert!(is_called.fetch_and(true, Ordering::Relaxed));
    }

    #[tokio::test]
    async fn read_packet_correctly_read_packet() {
        let raw_mgs = [
            100, // msg type
            0,   // msg flags
            0, 36, // msg size
            0, 0, 0, 1, // sender channel id
            0, 0, 4, 0, // initial window size
            0, 0, 4, 0, // maximum packet size
            116, 99, 112, 58, 47, 47, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 58, 52, 52,
            51, // destination url: tcp://google.com:443
        ];
        let receiver = JmuxReceiver::new(Box::new(MockAsyncReader {
            raw_msg: raw_mgs.to_vec(),
        }));

        let readed_msg = receiver.read_packet().await;

        assert!(readed_msg.is_ok());
        assert_eq!(raw_mgs.to_vec(), readed_msg.unwrap());
    }

    #[tokio::test]
    async fn receive_correctly_read_message() {
        let raw_mgs = [
            100, // msg type
            0,   // msg flags
            0, 36, // msg size
            0, 0, 0, 1, // sender channel id
            0, 0, 4, 0, // initial window size
            0, 0, 4, 0, // maximum packet size
            116, 99, 112, 58, 47, 47, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 58, 52, 52,
            51, // destination url: tcp://google.com:443
        ];
        let msg_example = JmuxChannelMsg::Open(JmuxMsgChannelOpen {
            initial_window_size: 1024,
            common_defs: CommonDefinitions {
                msg_size: 36,
                msg_flags: 0,
                msg_type: JmuxChannelMessageType::Open,
            },
            sender_channel_id: 1,
            maximum_packet_size: 1024,
            destination_url: "tcp://google.com:443".to_owned(),
        });
        let receiver = JmuxReceiver::new(Box::new(MockAsyncReader {
            raw_msg: raw_mgs.to_vec(),
        }));

        let readed_msg = receiver.receive().await;

        assert!(readed_msg.is_ok());
        assert_eq!(msg_example, readed_msg.unwrap());
    }

    #[test]
    fn channel_message_correctly_parse_message() {
        let raw_mgs = [
            100, // msg type
            0,   // msg flags
            0, 36, // msg size
            0, 0, 0, 1, // sender channel id
            0, 0, 4, 0, // initial window size
            0, 0, 4, 0, // maximum packet size
            116, 99, 112, 58, 47, 47, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 58, 52, 52,
            51, // destination url: tcp://google.com:443
        ];
        let msg_example = JmuxChannelMsg::Open(JmuxMsgChannelOpen {
            initial_window_size: 1024,
            common_defs: CommonDefinitions {
                msg_size: 36,
                msg_flags: 0,
                msg_type: JmuxChannelMessageType::Open,
            },
            sender_channel_id: 1,
            maximum_packet_size: 1024,
            destination_url: "tcp://google.com:443".to_owned(),
        });
        let receiver = JmuxReceiver::new(Box::new(MockAsyncReader {
            raw_msg: raw_mgs.to_vec(),
        }));

        let msg = receiver.parse_channel_message(&raw_mgs);

        assert!(msg.is_ok());
        assert_eq!(msg_example, msg.unwrap());
    }
}
