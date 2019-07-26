use tungstenite::WebSocket;
use hyper::upgrade::Upgraded;
use std::sync::{Mutex, Arc};
use std::io::{Read, Write};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio::io;
use log::{debug, error};
use crate::interceptor::PacketInterceptor;
use futures::{Async, Stream, Sink, AsyncSink};
use crate::transport::{Transport, JetStreamType, JetSinkType, JetFuture, JetStream, JetSink};
use url::Url;
use std::net::SocketAddr;
use tungstenite::Message;
use tungstenite::protocol::Role;
use tungstenite::client::AutoStream;
use crate::utils::url_to_socket_arr;
use std::error::Error;

pub enum WsStreamWrapper {
    Http((WebSocket<Upgraded>, Option<SocketAddr>)),
    Tls((WebSocket<AutoStream>, Option<SocketAddr>)),
}

impl WsStreamWrapper {
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            WsStreamWrapper::Http((_stream, addr)) => addr.clone(),
            WsStreamWrapper::Tls((_stream, addr)) => addr.clone(),
        }
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            WsStreamWrapper::Http((stream, _)) => stream.close(None).map(|()| ()).map_err(|_| io::Error::new(io::ErrorKind::NotFound, "".to_string())),
            WsStreamWrapper::Tls((stream, _)) => stream.close(None).map(|()| ()).map_err(|_| io::Error::new(io::ErrorKind::NotFound, "".to_string())),
        }
    }

    pub fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self {
            WsStreamWrapper::Http((stream, _)) => stream.close(None).map(|()| Async::Ready(())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
            WsStreamWrapper::Tls((stream, _)) => stream.close(None).map(|()| Async::Ready(())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }
}

impl Read for WsStreamWrapper {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) => {
                stream.read_message().map_err(|e| tungstenite_err_to_io_err(e)).and_then(move |m| {
                    buf.write(m.into_data().as_mut_slice())
                })
            }
            WsStreamWrapper::Tls((ref mut stream, _)) => {
                stream.read_message().map_err(|e| tungstenite_err_to_io_err(e)).and_then(move |m| {
                    buf.write(m.into_data().as_mut_slice())
                })
            }
        }
    }
}

impl Write for WsStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) =>
                stream.write_message(Message::Binary(buf.to_vec())).map(|_| buf.len()).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) =>
                stream.write_message(Message::Binary(buf.to_vec())).map(|_| buf.len()).map_err(|e| tungstenite_err_to_io_err(e)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) =>
                stream.write_pending().map(|_| ()).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) =>
                stream.write_pending().map(|_| ()).map_err(|e| tungstenite_err_to_io_err(e)),
        }
    }
}

impl AsyncRead for WsStreamWrapper {}

impl AsyncWrite for WsStreamWrapper {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) =>
                stream.close(None).map(|_| Async::Ready(())).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tls((ref mut stream, _)) =>
                stream.close(None).map(|_| Async::Ready(())).map_err(|e| tungstenite_err_to_io_err(e)),
        }
    }
}

pub struct WsTransport {
    stream: Arc<Mutex<WsStreamWrapper>>,
}

impl Clone for WsTransport {
    fn clone(&self) -> Self {
        WsTransport {
            stream: self.stream.clone(),
        }
    }
}

impl WsTransport {
    pub fn new_http(upgraded: Upgraded, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: Arc::new(Mutex::new(WsStreamWrapper::Http((WebSocket::from_raw_socket(upgraded, Role::Server, None), addr)))),
        }
    }

    pub fn new_tls(stream: WebSocket<AutoStream>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: Arc::new(Mutex::new(WsStreamWrapper::Tls((stream, addr)))),
        }
    }
}

impl Read for WsTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.read(&mut buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl AsyncRead for WsTransport {}

impl Write for WsTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.write(&buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.flush(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl AsyncWrite for WsTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.async_shutdown(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl Transport for WsTransport {
    fn connect(url: &Url) -> JetFuture<Self>
        where
            Self: Sized,
    {
        let addr = url_to_socket_arr(url);
        let owned_url = url.clone();
        Box::new(futures::lazy(move || {
            tungstenite::connect(owned_url).map(|(stream, _)| {
                WsTransport::new_tls(stream, Some(addr))
            }).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
        })) as JetFuture<Self>
    }

    fn message_sink(&self) -> JetSinkType<Vec<u8>> {
        Box::new(WsJetSink::new(self.stream.clone()))
    }

    fn message_stream(&self) -> JetStreamType<Vec<u8>> {
        Box::new(WsJetStream::new(self.stream.clone()))
    }
}

struct WsJetStream {
    stream: Arc<Mutex<WsStreamWrapper>>,
    nb_bytes_read: u64,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
}

impl WsJetStream {
    fn new(stream: Arc<Mutex<WsStreamWrapper>>) -> Self {
        WsJetStream {
            stream,
            nb_bytes_read: 0,
            packet_interceptor: None,
        }
    }
}

impl Stream for WsJetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if let Ok(ref mut stream) = self.stream.try_lock() {
            let mut buffer = [0u8; 65535];
            match stream.poll_read(&mut buffer) {
                Ok(Async::Ready(0)) => Ok(Async::Ready(None)),
                Ok(Async::Ready(len)) => {
                    let mut v = buffer.to_vec();
                    v.truncate(len);
                    self.nb_bytes_read += len as u64;
                    debug!("{} bytes read on {}", len, stream.peer_addr().unwrap());

                    if let Some(interceptor) = self.packet_interceptor.as_mut() {
                        interceptor.on_new_packet(stream.peer_addr(), &v);
                    }

                    Ok(Async::Ready(Some(v)))
                }
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(e) => {
                    error!("Can't read on socket: {}", dbg!(e));
                    Ok(Async::Ready(None))
                }
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl JetStream for WsJetStream {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let mut stream = self.stream.lock().unwrap();
        stream.shutdown()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        let stream = self.stream.lock().unwrap();
        stream.peer_addr()
    }

    fn nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read
    }

    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = Some(interceptor);
    }
}

struct WsJetSink {
    stream: Arc<Mutex<WsStreamWrapper>>,
    nb_bytes_written: u64,
}

impl WsJetSink {
    fn new(stream: Arc<Mutex<WsStreamWrapper>>) -> Self {
        WsJetSink {
            stream,
            nb_bytes_written: 0,
        }
    }

    fn _nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written
    }
}

impl Sink for WsJetSink {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        mut item: <Self as Sink>::SinkItem,
    ) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            debug!("{} bytes to write on {}", item.len(), stream.peer_addr().unwrap());
            match stream.poll_write(&item) {
                Ok(Async::Ready(len)) => {
                    if len > 0 {
                        self.nb_bytes_written += len as u64;
                        item.drain(0..len);
                        debug!("{} bytes written on {}", len, stream.peer_addr().unwrap())
                    } else {
                        debug!("0 bytes written on {}", stream.peer_addr().unwrap())
                    }

                    if item.is_empty() {
                        Ok(AsyncSink::Ready)
                    } else {
                        futures::task::current().notify();
                        Ok(AsyncSink::NotReady(item))
                    }
                }
                Ok(Async::NotReady) => Ok(AsyncSink::NotReady(item)),
                Err(e) => {
                    error!("Can't write on socket: {}", e);
                    Ok(AsyncSink::Ready)
                }
            }
        } else {
            Ok(AsyncSink::NotReady(item))
        }
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            stream.poll_flush()
        } else {
            Ok(Async::NotReady)
        }
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl JetSink for WsJetSink {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let mut stream = self.stream.lock().unwrap();
        stream.shutdown()
    }

    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written
    }
}


fn tungstenite_err_to_io_err(err: tungstenite::Error) -> io::Error {
    match err {
        tungstenite::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::Other, other.description()),
    }
}