use crate::http::HttpErrorStatus;
use crate::token::{JetAccessScope, JetAccessTokenClaims};
use saphir::prelude::*;

#[derive(Deserialize)]
pub enum JetTokenType {
    Scope(JetAccessScope),
    Bridge,
    Association,
}

pub struct AccessGuard {
    token_type: JetTokenType,
}

#[guard]
impl AccessGuard {
    pub fn new(token_type: JetTokenType) -> Self {
        AccessGuard { token_type }
    }

    async fn validate(&self, req: Request) -> Result<Request, HttpErrorStatus> {
        let claims = req
            .extensions()
            .get::<JetAccessTokenClaims>()
            .ok_or_else(|| HttpErrorStatus::unauthorized("identity missing (no token provided)"))?;

        let allowed = match (&self.token_type, claims) {
            (JetTokenType::Association, JetAccessTokenClaims::Association(_)) => true,
            (JetTokenType::Scope(scope_needed), JetAccessTokenClaims::Scope(scope_from_request))
                if scope_from_request.scope == *scope_needed =>
            {
                true
            }
            (JetTokenType::Bridge, JetAccessTokenClaims::Bridge(_)) => true,
            _ => false,
        };

        if allowed {
            Ok(req)
        } else {
            Err(HttpErrorStatus::forbidden("token not allowed"))
        }
    }
}
