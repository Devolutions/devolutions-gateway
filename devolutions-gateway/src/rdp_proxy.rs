use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::credential::ArcCredentialEntry;
use crate::proxy::Proxy;
use crate::session::{SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;

use anyhow::Context as _;
use ironrdp_acceptor::Acceptor;
use ironrdp_pdu::rdp::{capability_sets, client_info};
use ironrdp_pdu::{nego, x224};
use tokio::io::{AsyncRead, AsyncWrite};
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct RdpProxy<C, S> {
    conf: Arc<Conf>,
    session_info: SessionInfo,
    client_stream: C,
    client_addr: SocketAddr,
    server_stream: S,
    server_addr: SocketAddr,
    credential_entry: ArcCredentialEntry,
    leftover_bytes: bytes::BytesMut,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
}

impl<A, B> RdpProxy<A, B>
where
    A: AsyncWrite + AsyncRead + Unpin,
    B: AsyncWrite + AsyncRead + Unpin,
{
    pub async fn run(self) -> anyhow::Result<()> {
        handle(self).await
    }
}

#[allow(clippy::too_many_arguments)]
#[instrument("rdp_proxy", skip_all, fields(session_id = proxy.session_info.association_id.to_string(), target = proxy.server_addr.to_string()))]
async fn handle<C, S>(proxy: RdpProxy<C, S>) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let RdpProxy {
        conf,
        session_info,
        client_stream,
        client_addr,
        server_stream,
        server_addr,
        credential_entry,
        leftover_bytes,
        sessions,
        subscriber_tx,
    } = proxy;

    info!("RDP-TLS forwarding (credential injection)");

    Proxy::builder()
        .conf(conf)
        .session_info(session_info)
        .address_a(client_addr)
        .transport_a(client_stream)
        .address_b(server_addr)
        .transport_b(server_stream)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .build()
        .select_dissector_and_forward()
        .await
        .context("RDP-TLS traffic proxying failed")?;

    Ok(())
}

async fn forward_until_tls_upgrade(
    client_stream: impl AsyncWrite + AsyncRead + Unpin,
    server_stream: impl AsyncWrite + AsyncRead + Unpin,
) {
    let client_framed = ironrdp_tokio::TokioFramed::new(client_stream);
    let server_framed = ironrdp_tokio::TokioFramed::new(server_stream);

    loop {}

    let connection_confirm = ironrdp_core::decode::<x224::X224<nego::ConnectionConfirm>>(input)
        .map_err(ConnectorError::decode)
        .map(|p| p.0)?;

    debug!(message = ?connection_confirm, "Received");

    let (flags, selected_protocol) = match connection_confirm {
        nego::ConnectionConfirm::Response { flags, protocol } => (flags, protocol),
        nego::ConnectionConfirm::Failure { code } => {
            error!(?code, "Received connection failure code");
            return Err(reason_err!("Initiation", "{code}"));
        }
    };

    info!(?selected_protocol, ?flags, "Server confirmed connection");

    if !selected_protocol.intersects(requested_protocol) {
        return Err(reason_err!(
            "Initiation",
            "client advertised {requested_protocol}, but server selected {selected_protocol}",
        ));
    }

    let mut acceptor = Acceptor::new(security, size, capabilities, credentials);

    self.attach_channels(&mut acceptor);

    let res = ironrdp_acceptor::accept_begin(client_framed, &mut acceptor)
        .await
        .context("accept_begin failed")?;

    match res {
        BeginResult::ShouldUpgrade(stream) => {
            let tls_acceptor = match &self.opts.security {
                RdpServerSecurity::Tls(acceptor) => acceptor,
                RdpServerSecurity::Hybrid((acceptor, _)) => acceptor,
                RdpServerSecurity::None => unreachable!(),
            };
            let accept = match tls_acceptor.accept(stream).await {
                Ok(accept) => accept,
                Err(e) => {
                    warn!("Failed to TLS accept: {}", e);
                    return Ok(());
                }
            };
            let mut framed = TokioFramed::new(accept);

            acceptor.mark_security_upgrade_as_done();

            if let RdpServerSecurity::Hybrid((_, pub_key)) = &self.opts.security {
                // how to get the client name?
                // doesn't seem to matter yet
                let client_name = framed.get_inner().0.get_ref().0.peer_addr()?.to_string();

                ironrdp_acceptor::accept_credssp(&mut framed, &mut acceptor, client_name.into(), pub_key.clone(), None)
                    .await?;
            }

            self.accept_finalize(framed, acceptor).await?;
        }

        BeginResult::Continue(framed) => {
            self.accept_finalize(framed, acceptor).await?;
        }
    };
}
