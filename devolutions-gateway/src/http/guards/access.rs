use crate::http::HttpErrorStatus;
use jet_proto::token::{JetAccessScope, JetAccessTokenClaims};
use saphir::prelude::*;

#[derive(Deserialize)]
pub enum JetTokenType {
    Scope(JetAccessScope),
    Bridge,
    Association,
}

impl From<JetTokenType> for Vec<JetTokenType> {
    fn from(ty: JetTokenType) -> Self {
        vec![ty]
    }
}

pub struct AccessGuard {
    authorized_types: Vec<JetTokenType>,
}

#[guard]
impl AccessGuard {
    pub fn new(types: impl Into<Vec<JetTokenType>>) -> Self {
        AccessGuard {
            authorized_types: types.into(),
        }
    }

    async fn validate(&self, req: Request) -> Result<Request, HttpErrorStatus> {
        let claims = req
            .extensions()
            .get::<JetAccessTokenClaims>()
            .ok_or_else(|| HttpErrorStatus::unauthorized("identity missing (no token provided)"))?;

        let allowed = self.authorized_types.iter().any(|ty| match (ty, claims) {
            (JetTokenType::Association, JetAccessTokenClaims::Association(_)) => true,
            (JetTokenType::Scope(scope_needed), JetAccessTokenClaims::Scope(scope_from_request))
                if scope_from_request.scope == *scope_needed =>
            {
                true
            }
            (JetTokenType::Bridge, JetAccessTokenClaims::Bridge(_)) => true,
            _ => false,
        });

        if allowed {
            Ok(req)
        } else {
            Err(HttpErrorStatus::forbidden("token not allowed"))
        }
    }
}
