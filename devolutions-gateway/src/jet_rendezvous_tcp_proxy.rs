use crate::config::Conf;
use crate::http::controllers::association::start_remove_association_future;
use crate::jet::candidate::CandidateState;
use crate::jet_client::JetAssociationsMap;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use anyhow::Context;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use transport::Transport;
use typed_builder::TypedBuilder;
use uuid::Uuid;

#[derive(TypedBuilder)]
pub struct JetRendezvousTcpProxy {
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    client_transport: Transport,
    association_id: Uuid,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
}

impl JetRendezvousTcpProxy {
    pub async fn start(self, mut client_leftover: &[u8]) -> anyhow::Result<()> {
        let Self {
            conf,
            associations,
            mut client_transport,
            association_id,
            sessions,
            subscriber_tx,
        } = self;

        let (mut server_transport, server_leftover, info) = {
            let mut jet_associations = associations.lock();

            let assc = jet_associations
                .get_mut(&association_id)
                .with_context(|| format!("There is not {} association_id in JetAssociations map", association_id))?;

            let claims = assc.get_token_claims();

            if claims.jet_rec {
                anyhow::bail!("can't meet recording policy");
            }

            let info = SessionInfo::new(association_id, claims.jet_ap.clone(), ConnectionModeDetails::Rdv)
                .with_ttl(claims.jet_ttl)
                .with_recording_policy(claims.jet_rec)
                .with_filtering_policy(claims.jet_flt);

            let candidate = assc
                .get_first_accepted_tcp_candidate()
                .with_context(|| format!("There is not any candidates in {} JetAssociations map", association_id))?;

            let (transport, leftover) = candidate
                .take_transport()
                .expect("Candidate cannot be created without a transport");

            candidate.set_state(CandidateState::Connected);

            (transport, leftover, info)
        };

        server_transport
            .write_buf(&mut client_leftover)
            .await
            .context("Failed to write client leftover request")?;

        if let Some(bytes) = server_leftover {
            client_transport
                .write_all(&bytes)
                .await
                .context("Failed to write server leftover")?;
        }

        let proxy_result = Proxy::builder()
            .conf(conf)
            .session_info(info)
            .address_a(client_transport.addr)
            .transport_a(client_transport)
            .address_b(server_transport.addr)
            .transport_b(server_transport)
            .sessions(sessions)
            .subscriber_tx(subscriber_tx)
            .build()
            .forward()
            .await
            .context("An error occurred while running JetRendezvousTcpProxy");

        // remove association after a few minutes of inactivity
        start_remove_association_future(associations, association_id);

        proxy_result
    }
}
