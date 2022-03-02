use crate::http::controllers::association::start_remove_association_future;
use crate::jet::candidate::CandidateState;
use crate::jet_client::JetAssociationsMap;
use crate::proxy::Proxy;
use crate::{ConnectionModeDetails, GatewaySessionInfo};
use anyhow::Context;
use tokio::io::AsyncWriteExt;
use transport::AnyStream;
use typed_builder::TypedBuilder;
use uuid::Uuid;

#[derive(TypedBuilder)]
pub struct JetRendezvousTcpProxy {
    associations: JetAssociationsMap,
    client_transport: AnyStream,
    association_id: Uuid,
}

impl JetRendezvousTcpProxy {
    pub async fn start(self, mut client_leftover: &[u8]) -> anyhow::Result<()> {
        let Self {
            associations,
            mut client_transport,
            association_id,
        } = self;

        let (mut server_transport, server_leftover, info) = {
            let mut jet_associations = associations.lock();

            let assc = jet_associations
                .get_mut(&association_id)
                .with_context(|| format!("There is not {} association_id in JetAssociations map", association_id))?;

            let claims = assc.get_token_claims();

            let info = GatewaySessionInfo::new(association_id, claims.jet_ap, ConnectionModeDetails::Rdv)
                .with_recording_policy(claims.jet_rec)
                .with_filtering_policy(claims.jet_flt);

            if claims.jet_rec {
                anyhow::bail!("can't meet recording policy");
            }

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

        client_transport
            .write_all(&server_leftover)
            .await
            .context("Failed to write server leftover")?;

        let proxy_result = Proxy::init()
            .session_info(info)
            .transports(client_transport, server_transport)
            .forward()
            .await
            .context("An error occurred while running JetRendezvousTcpProxy");

        // remove association after a few minutes of inactivity
        start_remove_association_future(associations, association_id);

        proxy_result
    }
}
