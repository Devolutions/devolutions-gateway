use crate::config::Config;
use crate::http::controllers::association::start_remove_association_future;
use crate::jet::candidate::CandidateState;
use crate::jet_client::JetAssociationsMap;
use crate::proxy::Proxy;
use crate::transport::JetTransport;
use crate::{ConnectionModeDetails, GatewaySessionInfo};
use anyhow::Context;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub struct JetRendezvousTcpProxy {
    jet_associations: JetAssociationsMap,
    client_transport: JetTransport,
    association_id: Uuid,
}

impl JetRendezvousTcpProxy {
    pub fn new(jet_associations: JetAssociationsMap, client_transport: JetTransport, association_id: Uuid) -> Self {
        Self {
            jet_associations,
            client_transport,
            association_id,
        }
    }

    pub async fn proxy(self, config: Arc<Config>, mut leftover_request: &[u8]) -> anyhow::Result<()> {
        let Self {
            jet_associations,
            client_transport,
            association_id,
        } = self;

        let (mut server_transport, info) = {
            let mut jet_associations = jet_associations.lock().await;

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

            let transport = candidate
                .take_transport()
                .expect("Candidate cannot be created without a transport");

            candidate.set_state(CandidateState::Connected);
            candidate.set_client_nb_bytes_read(client_transport.clone_nb_bytes_read());
            candidate.set_client_nb_bytes_written(client_transport.clone_nb_bytes_written());

            (transport, info)
        };

        server_transport
            .write_buf(&mut leftover_request)
            .await
            .context("Failed to write leftover request")?;

        let proxy_result = Proxy::new(config, info)
            .build_with_message_reader(server_transport, client_transport, None)
            .await
            .context("An error occurred while running JetRendezvousTcpProxy");

        // remove association after a few minutes of inactivity
        start_remove_association_future(jet_associations, association_id);

        proxy_result
    }
}
