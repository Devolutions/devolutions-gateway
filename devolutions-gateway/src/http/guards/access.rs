use jet_proto::token::{JetAccessScope, JetAccessTokenClaims};
use saphir::prelude::*;

#[derive(Deserialize)]
pub enum JetAccessType {
    Scope(JetAccessScope),
    Session,
}

pub struct AccessGuard {
    access_type: JetAccessType,
}

#[guard]
impl AccessGuard {
    pub fn new(access_type: JetAccessType) -> Self {
        AccessGuard { access_type }
    }

    async fn validate(&self, req: Request) -> Result<Request, StatusCode> {
        if let Some(claims) = req.extensions().get::<JetAccessTokenClaims>() {
            match (claims, &self.access_type) {
                (JetAccessTokenClaims::Session(_), JetAccessType::Session) => {
                    return Ok(req);
                }
                (JetAccessTokenClaims::Scope(scope_from_request), JetAccessType::Scope(scope_needed))
                    if scope_from_request.scope == *scope_needed =>
                {
                    return Ok(req);
                }
                _ => {}
            }
        }

        Err(StatusCode::FORBIDDEN)
    }
}
