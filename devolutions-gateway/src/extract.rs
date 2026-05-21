use std::net::SocketAddr;

use axum::Extension;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Path, RawQuery, Request};
use axum::http::request::Parts;

use crate::DgwState;
use crate::http::HttpError;
use crate::token::{
    AccessScope, AccessTokenClaims, AssociationTokenClaims, BridgeTokenClaims, JmuxTokenClaims, JrecTokenClaims,
    JrlTokenClaims, KdcTokenClaims, ScopeTokenClaims, WebAppTokenClaims,
};

#[derive(Clone)]
pub struct AccessToken(pub AccessTokenClaims);

impl<S> FromRequestParts<S> for AccessToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Extension::<AccessTokenClaims>::from_request_parts(parts, state)
            .await
            .map_err(HttpError::internal().err())?
            .0;
        Ok(Self(claims))
    }
}

#[derive(Clone)]
pub struct AssociationToken(pub AssociationTokenClaims);

impl<S> FromRequestParts<S> for AssociationToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Association(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected ASSOCIATION)"))
        }
    }
}

#[derive(Clone)]
pub struct JrlToken(pub JrlTokenClaims);

impl<S> FromRequestParts<S> for JrlToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Jrl(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected JRL)"))
        }
    }
}

#[derive(Clone)]
pub struct JrecToken(pub JrecTokenClaims);

impl<S> FromRequestParts<S> for JrecToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Jrec(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected JREC)"))
        }
    }
}

#[derive(Clone)]
pub struct JmuxToken(pub JmuxTokenClaims);

impl<S> FromRequestParts<S> for JmuxToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Jmux(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected JMUX)"))
        }
    }
}

/// Extractor for the KDC proxy route's path-bound token.
///
/// `/jet/KdcProxy/{token}` carries the token in the URL path rather than the standard
/// `Authorization: Bearer` header or `?token=` query parameter, so the global auth middleware
/// (`middleware/auth.rs`) skips it (see `AUTH_EXCEPTIONS`). This extractor reads the token from
/// the path, runs it through the same `authenticate()` routine the middleware would, and
/// unwraps the `Kdc` variant so handlers receive `KdcTokenClaims` directly.
#[derive(Clone)]
pub struct KdcToken(pub KdcTokenClaims);

impl FromRequestParts<DgwState> for KdcToken {
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &DgwState) -> Result<Self, Self::Rejection> {
        let Path(token) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(HttpError::bad_request().with_msg("KDC token missing from path").err())?;
        let ConnectInfo(source_addr) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(HttpError::internal().with_msg("source address unavailable").err())?;

        let conf = state.conf_handle.get_conf();
        let claims = crate::middleware::auth::authenticate(
            source_addr,
            &token,
            &conf,
            &state.token_cache,
            &state.jrl,
            &state.recordings.active_recordings,
            None,
        )
        .map_err(HttpError::unauthorized().err())?;

        match claims {
            AccessTokenClaims::Kdc(claims) => Ok(Self(claims)),
            _ => Err(HttpError::forbidden().msg("token not allowed (expected KDC token)")),
        }
    }
}

#[derive(Clone)]
pub struct ScopeToken(pub ScopeTokenClaims);

impl<S> FromRequestParts<S> for ScopeToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Scope(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected SCOPE)"))
        }
    }
}

#[derive(Clone, Copy)]
pub struct SessionsReadScope;

impl<S> FromRequestParts<S> for SessionsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::SessionsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct SessionTerminateScope;

impl<S> FromRequestParts<S> for SessionTerminateScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::SessionTerminate => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct AssociationsReadScope;

impl<S> FromRequestParts<S> for AssociationsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::AssociationsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DiagnosticsReadScope;

impl<S> FromRequestParts<S> for DiagnosticsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::DiagnosticsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct JrlReadScope;

impl<S> FromRequestParts<S> for JrlReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::JrlRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ConfigWriteScope;

impl<S> FromRequestParts<S> for ConfigWriteScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::ConfigWrite => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct HeartbeatReadScope;

impl<S> FromRequestParts<S> for HeartbeatReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::HeartbeatRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct RecordingDeleteScope;

impl<S> FromRequestParts<S> for RecordingDeleteScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::RecordingDelete => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct RecordingsReadScope;

impl<S> FromRequestParts<S> for RecordingsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::RecordingsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct UpdateScope;

impl<S> FromRequestParts<S> for UpdateScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::Update => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct UpdateReadScope;

impl<S> FromRequestParts<S> for UpdateReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            // The full write scope also grants read access.
            AccessScope::Update => Ok(Self),
            AccessScope::UpdateRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct PreflightScope;

impl<S> FromRequestParts<S> for PreflightScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::Preflight => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct TrafficClaimScope;

impl<S> FromRequestParts<S> for TrafficClaimScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::TrafficClaim => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct TrafficAckScope;

impl<S> FromRequestParts<S> for TrafficAckScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::TrafficAck => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetMonitorConfigScope;

impl<S> FromRequestParts<S> for NetMonitorConfigScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::NetMonitorConfig => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetMonitorDrainScope;

impl<S> FromRequestParts<S> for NetMonitorDrainScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::NetMonitorDrain => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

/// Grants read access to agent management endpoints.
///
/// Accepts a scope token with `AgentRead` or `Wildcard` scope.
#[derive(Clone, Copy)]
pub struct AgentManagementReadAccess;

impl<S> FromRequestParts<S> for AgentManagementReadAccess
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Extension::<AccessTokenClaims>::from_request_parts(parts, state)
            .await
            .map_err(HttpError::internal().err())?
            .0;

        match claims {
            AccessTokenClaims::Scope(scope) => match scope.scope {
                AccessScope::Wildcard | AccessScope::AgentRead => Ok(Self),
                _ => Err(HttpError::forbidden()
                    .msg("invalid scope for agent management read (require one of: gateway.agent.read, *)")),
            },
            _ => Err(HttpError::forbidden().msg("scope token required for agent management read")),
        }
    }
}

/// Grants write access to agent management endpoints.
///
/// Accepts scope tokens with `AgentEnroll` or `Wildcard` scope. A dedicated
/// `AgentDelete` scope will replace `AgentEnroll` here in a follow-up PR.
#[derive(Clone, Copy)]
pub struct AgentManagementWriteAccess;

impl<S> FromRequestParts<S> for AgentManagementWriteAccess
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Extension::<AccessTokenClaims>::from_request_parts(parts, state)
            .await
            .map_err(HttpError::internal().err())?
            .0;

        match claims {
            AccessTokenClaims::Scope(scope) => match scope.scope {
                AccessScope::Wildcard | AccessScope::AgentEnroll => Ok(Self),
                _ => Err(HttpError::forbidden()
                    .msg("invalid scope for agent management write (require one of: gateway.agent.enroll, *)")),
            },
            _ => Err(HttpError::forbidden().msg("scope token required for agent management write")),
        }
    }
}

#[derive(Clone)]
pub struct WebAppToken(pub WebAppTokenClaims);

impl<S> FromRequestParts<S> for WebAppToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::WebApp(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected WEBAPP)"))
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetScanToken;

impl<S> FromRequestParts<S> for NetScanToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::NetScan(_) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self)
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected NETSCAN)"))
        }
    }
}

#[derive(Clone)]
pub struct BridgeToken(pub BridgeTokenClaims);

impl<S> FromRequestParts<S> for BridgeToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Bridge(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected BRIDGE)"))
        }
    }
}

pub struct RepeatQuery<T>(pub(crate) T);

impl<T, S> FromRequest<S> for RepeatQuery<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let RawQuery(query) = RawQuery::from_request(req, state)
            .await
            .map_err(|e| HttpError::bad_request().build(e))?;

        let query = query.unwrap_or_default();
        let parsed_query = serde_querystring::from_str::<T>(&query, serde_querystring::ParseMode::Duplicate)
            .map_err(|e| HttpError::bad_request().build(e))?;

        Ok(RepeatQuery(parsed_query))
    }
}
