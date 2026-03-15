use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use nonempty::NonEmpty;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::target_addr::TargetAddr;
use crate::utils;
use crate::wireguard::{VirtualTcpStream, WireGuardHandle};

pub enum ServerStream {
    Direct(tokio::net::TcpStream),
    Virtual(VirtualTcpStream),
}

impl AsyncRead for ServerStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ServerStream::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            ServerStream::Virtual(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ServerStream::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
            ServerStream::Virtual(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ServerStream::Direct(stream) => Pin::new(stream).poll_flush(cx),
            ServerStream::Virtual(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ServerStream::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            ServerStream::Virtual(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub async fn connect_target(
    wireguard_listener: Option<&WireGuardHandle>,
    association_id: Uuid,
    explicit_agent_id: Option<Uuid>,
    targets: &NonEmpty<TargetAddr>,
) -> anyhow::Result<((ServerStream, SocketAddr), TargetAddr)> {
    // Agent routing is strictly opt-in.
    // If the token does not carry `jet_agent_id`, Gateway must stay on the regular direct path.
    if let Some(agent_id) = explicit_agent_id {
        let wg_listener = wireguard_listener
            .as_ref()
            .context("WireGuard not configured but jet_agent_id is present in token")?;

        tracing::info!(%agent_id, %association_id, "Routing connection via WireGuard agent");

        let mut targets_vec = Vec::with_capacity(1 + targets.tail.len());
        targets_vec.push(targets.head.clone());
        targets_vec.extend_from_slice(&targets.tail);

        let (virtual_stream, addr, target) = wg_listener.connect_via_agent(agent_id, &targets_vec).await?;
        return Ok(((ServerStream::Virtual(virtual_stream), addr), target));
    }

    let ((stream, addr), target) = utils::successive_try(targets, utils::tcp_connect).await?;
    Ok(((ServerStream::Direct(stream), addr), target.clone()))
}
