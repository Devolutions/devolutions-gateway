use crate::config::Config;
use crate::http::controllers::jet::start_remove_association_future;
use crate::jet::candidate::CandidateState;
use crate::jet_client::JetAssociationsMap;
use crate::proxy::Proxy;
use crate::transport::JetTransport;
use crate::utils::into_other_io_error;
use slog_scope::error;
use std::io;
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

    pub async fn proxy(self, config: Arc<Config>, mut leftover_request: &[u8]) -> Result<(), io::Error> {
        let Self {
            jet_associations,
            client_transport,
            association_id,
        } = self;

        let (mut server_transport, session_token) = {
            let mut jet_associations = jet_associations.lock().await;

            let assc = jet_associations.get_mut(&association_id).ok_or_else(|| {
                into_other_io_error(format!(
                    "There is not {} association_id in JetAssociations map",
                    association_id
                ))
            })?;

            let candidate = assc.get_first_accepted_tcp_candidate().ok_or_else(|| {
                into_other_io_error(format!(
                    "There is not any candidates in {} JetAssociations map",
                    association_id
                ))
            })?;

            let transport = candidate
                .take_transport()
                .expect("Candidate cannot be created without a transport");

            candidate.set_state(CandidateState::Connected);
            candidate.set_client_nb_bytes_read(client_transport.clone_nb_bytes_read());
            candidate.set_client_nb_bytes_written(client_transport.clone_nb_bytes_written());

            (transport, assc.jet_session_token_claims().clone())
        };

        server_transport.write_buf(&mut leftover_request).await.map_err(|e| {
            error!("Failed to write leftover request: {}", e);
            e
        })?;

        let proxy_result = Proxy::new(config, session_token.into())
            .build_with_message_reader(server_transport, client_transport, None)
            .await
            .map_err(|e| {
                error!("An error occurred while running JetRendezvousTcpProxy: {}", e);
                e
            });

        // remove association after a few minutes of inactivity
        start_remove_association_future(jet_associations, association_id).await;

        proxy_result
    }
}
