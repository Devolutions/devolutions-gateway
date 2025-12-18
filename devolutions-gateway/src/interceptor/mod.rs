use std::pin::Pin;
use std::{io, task};

use bytes::BytesMut;
use pin_project_lite::pin_project;
use tap::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod pcap;
pub mod plugin_recording;

pin_project! {
    pub struct Interceptor<S> {
        #[pin]
        pub inner: S,
        pub inspectors: Vec<Box<dyn Inspector + Send>>,
    }
}

impl<S> Interceptor<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            inspectors: Vec::new(),
        }
    }
}

impl<S> AsyncRead for Interceptor<S>
where
    S: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.project();

        match futures::ready!(this.inner.poll_read(cx, buf)) {
            Ok(()) => {}
            Err(e) => return task::Poll::Ready(Err(e)),
        }

        let filled = buf.filled();

        for inspector in this.inspectors {
            if let Err(e) = inspector.inspect_bytes(filled) {
                debug!("inspector error: {}", e);
            }
        }

        task::Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for Interceptor<S>
where
    S: AsyncWrite,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> task::Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pub trait Inspector {
    /// Inspect traffic intercepted by `Interceptor`.
    ///
    /// This should execute as fast as possible (consider using a separate task for the heavy lifting).
    fn inspect_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()>;
}

#[derive(Clone, Copy, Debug)]
pub enum PeerSide {
    Client,
    Server,
}

pub trait Dissector {
    /// Returns bytes containing a whole message leaving remaining bytes messages in the input
    /// buffer.
    fn dissect_one(&mut self, side: PeerSide, bytes: &mut BytesMut) -> Option<BytesMut>;

    fn dissect_all(&mut self, side: PeerSide, bytes: &mut BytesMut) -> Vec<BytesMut> {
        let mut all = Vec::new();
        while let Some(one) = self.dissect_one(side, bytes) {
            all.push(one);
        }
        all
    }
}

pub struct DummyDissector;

impl Dissector for DummyDissector {
    fn dissect_one(&mut self, _: PeerSide, bytes: &mut BytesMut) -> Option<BytesMut> {
        if bytes.is_empty() {
            None
        } else {
            Some(std::mem::take(bytes))
        }
    }
}

pub struct WaykDissector;

impl Dissector for WaykDissector {
    fn dissect_one(&mut self, _: PeerSide, bytes: &mut BytesMut) -> Option<BytesMut> {
        let header = <[u8; 4]>::try_from(bytes.get(..4)?).ok()?.pipe(u32::from_le_bytes);

        let msg_size = if header & 0x8000_0000 != 0 {
            usize::try_from(header & 0x0000_FFFF).expect("< 0xFFFF") + 4
        } else {
            usize::try_from(header & 0x07FF_FFFF).expect("< 0x07FF_FFFF") + 6
        };

        if bytes.len() >= msg_size {
            Some(bytes.split_to(msg_size))
        } else {
            None
        }
    }
}
