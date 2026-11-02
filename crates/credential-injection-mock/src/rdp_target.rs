//! RDP targets that never finish a handshake: one records the X.224 cookie Gateway forwards,
//! the other only counts the connections it gets.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context as _;
use ironrdp_pdu::nego::{ConnectionRequest, NegoRequestData};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::TokioFramed;
use tokio::net::{TcpListener, TcpStream};

use crate::event::{Event, emit};

pub(crate) async fn run_rdp_target() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind fake RDP target")?;
    let port = listener.local_addr().context("fake RDP local_addr")?.port();
    emit(&Event::Listening { port });

    loop {
        let (stream, _) = listener.accept().await.context("accept on fake RDP target")?;
        emit(&Event::Accepted);
        tokio::spawn(async move {
            let mut framed = TokioFramed::new(stream);
            // CredSSP cert generation can delay the rewritten X.224 CR.
            if let Ok(Ok((_, request))) = tokio::time::timeout(Duration::from_secs(30), framed.read_pdu()).await
                && let Ok(cr) = ironrdp_core::decode::<X224<ConnectionRequest>>(&request)
            {
                emit_cookie(&cr);
            }
            // Keep the accepted socket open so the proxy can finish writing the CR.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
    }
}

/// Accepts connections and never speaks; proves the proxy did (or did not) dial the target.
pub(crate) async fn run_closed_target() -> anyhow::Result<()> {
    let listener = LocalhostListener::bind().await.context("bind closed target")?;
    emit(&Event::Listening { port: listener.port()? });

    loop {
        let (_stream, _) = listener.accept().await.context("accept on closed target")?;
        emit(&Event::Accepted);
    }
}

pub(crate) fn emit_cookie(cr: &X224<ConnectionRequest>) {
    if let Some(NegoRequestData::Cookie(cookie)) = &cr.0.nego_data {
        emit(&Event::Cookie { cookie: &cookie.0 });
    }
}

/// Listens on 127.0.0.1 and ::1 at one port, for targets reached as `localhost`.
///
/// Windows resolves `localhost` to ::1 first, and a wildcard listener raises a firewall prompt.
pub(crate) struct LocalhostListener {
    v4: TcpListener,
    v6: Option<TcpListener>,
}

impl LocalhostListener {
    pub(crate) async fn bind() -> anyhow::Result<Self> {
        let v4 = TcpListener::bind("127.0.0.1:0").await.context("bind 127.0.0.1")?;
        let port = v4.local_addr().context("loopback local_addr")?.port();
        let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await.ok();
        Ok(Self { v4, v6 })
    }

    pub(crate) fn port(&self) -> anyhow::Result<u16> {
        Ok(self.v4.local_addr().context("loopback local_addr")?.port())
    }

    pub(crate) async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        match &self.v6 {
            Some(v6) => tokio::select! {
                accepted = self.v4.accept() => accepted,
                accepted = v6.accept() => accepted,
            },
            None => self.v4.accept().await,
        }
    }
}
