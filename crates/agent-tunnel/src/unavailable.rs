use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use uuid::Uuid;

use crate::AgentRegistry;

#[derive(Clone)]
pub struct AgentTunnelHandle {
    registry: Arc<AgentRegistry>,
}

impl AgentTunnelHandle {
    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub async fn connect_via_agent(
        &self,
        _agent_id: Uuid,
        _session_id: Uuid,
        _target: &str,
    ) -> anyhow::Result<TunnelStream> {
        anyhow::bail!("agent tunnel is not available in FIPS mode")
    }
}

pub struct TunnelStream(DuplexStream);

impl AsyncRead for TunnelStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
