use jet_proto::JET_VERSION_V2;

use saphir::controller::Controller;
use saphir::http::{header, Method, StatusCode};
use saphir::macros::controller;
use saphir::request::Request;
use slog_scope::info;
use std::sync::Arc;
use tokio_02::runtime::Handle;
use tokio_compat_02::FutureExt;
use uuid::Uuid;

use crate::config::Config;
use crate::http::controllers::health::build_health_response;
use crate::http::middlewares::auth::{parse_auth_header, AuthHeaderType};
use crate::jet::association::{Association, AssociationResponse};
use crate::jet::candidate::Candidate;
use crate::jet_client::JetAssociationsMap;
use crate::utils::association::{remove_jet_association, ACCEPT_REQUEST_TIMEOUT};

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
    async fn create_association(&self, req: Request) -> (StatusCode, ()) {
        let association_id = match req
            .captures()
            .get("association_id")
            .and_then(|id| Uuid::parse_str(id).ok())
        {
            Some(id) => id,
            None => return (StatusCode::BAD_REQUEST, ()),
        };

        // check the session token is signed by our provider if unrestricted mode is not set
        let mut jet_tp_claim: Option<String> = None;
        jet_tp_claim = match validate_session_token(self.config.as_ref(), &req) {
            Err(e) => {
                slog_scope::error!("Couldn't validate session token: {}", e);
                return (StatusCode::UNAUTHORIZED, ());
            }
            Ok(expected_token) => {
                if !self.config.unrestricted &&
                    (!expected_token.den_session_id.is_some() || expected_token.den_session_id.unwrap() != association_id) {
                    slog_scope::error!(
                        "Invalid session token: expected {:?}, got {}",
                        expected_token.den_session_id,
                        association_id
                    );
                    return (StatusCode::FORBIDDEN, ());
                } else {
                    expected_token.jet_tp
                }
            }
        };

        slog_scope::debug!("The jet_tp claim is {:?}", jet_tp_claim);

        // Controller runs by Saphir via tokio 0.2 runtime, we need to use .compat()
        // to run Mutex from tokio 0.3 via Saphir's tokio 0.2 runtime. This code should be upgraded
        // when saphir perform transition to tokio 0.3
        let mut jet_associations = self.jet_associations.lock().compat().await;

        jet_associations.insert(association_id, Association::new(association_id, JET_VERSION_V2, jet_tp_claim));
        start_remove_association_future(self.jet_associations.clone(), association_id).await;

        (StatusCode::OK, ())
    }

    #[post("/association/<association_id>/candidates")]
    async fn gather_association_candidates(&self, req: Request) -> (StatusCode, Option<String>) {
        let association_id = match req
            .captures()
            .get("association_id")
            .and_then(|id| Uuid::parse_str(id).ok())
        {
            Some(id) => id,
            None => return (StatusCode::BAD_REQUEST, None),
        };

        // check the session token is signed by our provider if unrestricted mode is not set
        let mut jet_tp_claim: Option<String> = None;
        jet_tp_claim = match validate_session_token(self.config.as_ref(), &req) {
            Err(e) => {
                slog_scope::error!("Couldn't validate session token: {}", e);
                return (StatusCode::UNAUTHORIZED, None);
            }
            Ok(expected_token) => {
                if !self.config.unrestricted &&
                    (!expected_token.den_session_id.is_some() || expected_token.den_session_id.unwrap() != association_id) {
                    slog_scope::error!(
                        "Invalid session token: expected {:?}, got {}",
                        expected_token.den_session_id,
                        association_id
                    );
                    return (StatusCode::FORBIDDEN, None);
                } else {
                    expected_token.jet_tp
                }
            }
        };

        slog_scope::debug!("The jet_tp claim is {:?}", jet_tp_claim);

        // create association
        let mut jet_associations = self.jet_associations.lock().compat().await;

        if !jet_associations.contains_key(&association_id) {
            jet_associations.insert(association_id, Association::new(association_id, JET_VERSION_V2, jet_tp_claim));
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



#[derive(Deserialize)]
struct PartialSessionToken {
    den_session_id: Option<Uuid>,
    jet_tp: Option<String>
}

fn validate_session_token(config: &Config, req: &Request) -> Result<PartialSessionToken, String> {
    let key = config
        .provisioner_public_key
        .as_ref()
        .ok_or_else(|| "Provisioner public key is missing".to_string())?;

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| "Authorization header not present in request.".to_string())?;

    let auth_str = auth_header.to_str().map_err(|e| e.to_string())?;

    match parse_auth_header(auth_str) {
        Some((AuthHeaderType::Bearer, token)) => {
            use picky::jose::jwt::{JwtSig, JwtValidator};
            let jwt = JwtSig::<PartialSessionToken>::decode(&token, key, &JwtValidator::no_check())
                .map_err(|e| format!("Invalid session token: {:?}", e))?;

            Ok(PartialSessionToken {
                den_session_id: jwt.claims.den_session_id,
                jet_tp: jwt.claims.jet_tp,
            })
        }
        _ => Err("Invalid authorization type".to_string()),
    }
}