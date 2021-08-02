use crate::config::Config;
use crate::http::controllers::health::build_health_response;
use crate::http::guards::access::{AccessGuard, JetAccessType};
use crate::jet::association::{Association, AssociationResponse};
use crate::jet::candidate::Candidate;
use crate::jet_client::JetAssociationsMap;
use crate::utils::association::{remove_jet_association, ACCEPT_REQUEST_TIMEOUT};
use jet_proto::token::JetAccessTokenClaims;
use jet_proto::JET_VERSION_V2;
use saphir::controller::Controller;
use saphir::http::{Method, StatusCode};
use saphir::macros::controller;
use saphir::request::Request;
use slog_scope::info;
use std::sync::Arc;
use tokio_02::runtime::Handle;
use tokio_compat_02::FutureExt;
use uuid::Uuid;

pub struct JetController {
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
}

impl JetController {
    pub fn new(config: Arc<Config>, jet_associations: JetAssociationsMap) -> Self {
        Self {
            config,
            jet_associations,
        }
    }
}

#[controller(name = "jet")]
impl JetController {
    #[get("/association")]
    async fn get_associations(&self, detail: Option<bool>) -> (StatusCode, Option<String>) {
        let with_detail = detail.unwrap_or(false);
        let associations_response: Vec<AssociationResponse>;
        let associations = self.jet_associations.lock().compat().await;

        associations_response = associations
            .values()
            .map(|association| AssociationResponse::from(association, with_detail))
            .collect();

        if let Ok(body) = serde_json::to_string(&associations_response) {
            return (StatusCode::OK, Some(body));
        }

        (StatusCode::BAD_REQUEST, None)
    }

    #[post("/association/<association_id>")]
    #[guard(AccessGuard, init_expr = r#"JetAccessType::Session"#)]
    async fn create_association(&self, req: Request) -> (StatusCode, ()) {
        if let Some(JetAccessTokenClaims::Session(session_token)) = req.extensions().get::<JetAccessTokenClaims>() {
            let association_id = match req
                .captures()
                .get("association_id")
                .and_then(|id| Uuid::parse_str(id).ok())
            {
                Some(id) => id,
                None => return (StatusCode::BAD_REQUEST, ()),
            };

            if session_token.jet_aid != association_id {
                slog_scope::error!(
                    "Invalid session token: expected {}, got {}",
                    session_token.jet_aid.to_string(),
                    association_id
                );
                return (StatusCode::FORBIDDEN, ());
            }

            // Controller runs by Saphir via tokio 0.2 runtime, we need to use .compat()
            // to run Mutex from tokio 0.3 via Saphir's tokio 0.2 runtime. This code should be upgraded
            // when saphir perform transition to tokio 0.3
            let mut jet_associations = self.jet_associations.lock().compat().await;

            jet_associations.insert(
                association_id,
                Association::new(association_id, JET_VERSION_V2, session_token.clone()),
            );
            start_remove_association_future(self.jet_associations.clone(), association_id).await;

            (StatusCode::OK, ())
        } else {
            (StatusCode::UNAUTHORIZED, ())
        }
    }

    #[post("/association/<association_id>/candidates")]
    #[guard(AccessGuard, init_expr = r#"JetAccessType::Session"#)]
    async fn gather_association_candidates(&self, req: Request) -> (StatusCode, Option<String>) {
        if let Some(JetAccessTokenClaims::Session(session_token)) = req.extensions().get::<JetAccessTokenClaims>() {
            let association_id = match req
                .captures()
                .get("association_id")
                .and_then(|id| Uuid::parse_str(id).ok())
            {
                Some(id) => id,
                None => return (StatusCode::BAD_REQUEST, None),
            };

            if session_token.jet_aid != association_id {
                slog_scope::error!(
                    "Invalid session token: expected {}, got {}",
                    session_token.jet_aid.to_string(),
                    association_id
                );
                return (StatusCode::FORBIDDEN, None);
            }

            // create association if needed

            let mut jet_associations = self.jet_associations.lock().compat().await;

            if let std::collections::hash_map::Entry::Vacant(e) = jet_associations.entry(association_id) {
                e.insert(Association::new(association_id, JET_VERSION_V2, session_token.clone()));
                start_remove_association_future(self.jet_associations.clone(), association_id).await;
            }

            let association = jet_associations
                .get_mut(&association_id)
                .expect("presence is checked above");

            if association.get_candidates().is_empty() {
                for listener in &self.config.listeners {
                    if let Some(candidate) = Candidate::new(&listener.external_url.to_string().trim_end_matches('/')) {
                        association.add_candidate(candidate);
                    }
                }
            }

            (StatusCode::OK, Some(association.gather_candidate().to_string()))
        } else {
            (StatusCode::UNAUTHORIZED, None)
        }
    }

    #[get("/health")]
    async fn health(&self) -> (StatusCode, String) {
        build_health_response(&self.config)
    }
}

pub async fn start_remove_association_future(jet_associations: JetAssociationsMap, uuid: Uuid) {
    remove_association(jet_associations, uuid).await;
}

pub async fn remove_association(jet_associations: JetAssociationsMap, uuid: Uuid) {
    if let Ok(runtime_handle) = Handle::try_current() {
        runtime_handle.spawn(async move {
            tokio_02::time::delay_for(ACCEPT_REQUEST_TIMEOUT).await;
            if remove_jet_association(jet_associations, uuid, None).compat().await {
                info!(
                    "No connect request received with association {}. Association removed!",
                    uuid
                );
            }
        });
    }
}
