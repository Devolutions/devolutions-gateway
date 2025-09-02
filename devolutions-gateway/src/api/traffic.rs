use axum::extract::{Query, State};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use traffic_audit::{EventOutcome, TrafficEvent, TransportProtocol};
use uuid::Uuid;

use crate::extract::{TrafficAckScope, TrafficClaimScope};
use crate::http::{HttpError, HttpErrorBuilder};

const DEFAULT_CONSUMER: &str = "provisioner";

pub fn make_router<S>(state: crate::DgwState) -> Router<S> {
    Router::new()
        .route("/claim", axum::routing::post(post_traffic_claim))
        .route("/ack", axum::routing::post(post_traffic_ack))
        .with_state(state)
}

/// Claim traffic audit events for processing
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "ClaimTrafficEvents",
    tag = "Traffic",
    path = "/jet/traffic/claim",
    params(ClaimQuery),
    responses(
        (status = 200, description = "Successfully claimed traffic events", body = Vec<ClaimedTrafficEvent>),
        (status = 400, description = "Invalid query parameters"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Internal server error"),
    ),
    security(("scope_token" = ["gateway.traffic.claim"])),
))]
pub async fn post_traffic_claim(
    _scope: TrafficClaimScope,
    State(state): State<crate::DgwState>,
    Query(q): Query<ClaimQuery>,
) -> Result<Json<Vec<ClaimedTrafficEvent>>, HttpError> {
    if q.max < 1 || q.max > 1000 {
        return Err(HttpError::bad_request().msg("max must be between 1 and 1000"));
    }

    if q.lease_ms < 1_000 || q.lease_ms > 3_600_000 {
        return Err(HttpError::bad_request().msg("lease_ms must be between 1000 and 3600000"));
    }

    let handle = &state.traffic_audit_handle;

    let items = handle
        .claim(DEFAULT_CONSUMER, q.lease_ms, q.max)
        .await
        .map_err(HttpError::internal().err())?;

    // Convert to response format and ensure ascending id order
    let mut response_items: Vec<ClaimedTrafficEvent> = items
        .into_iter()
        .map(|claimed| ClaimedTrafficEvent {
            id: claimed.id,
            event: claimed.event.into(),
        })
        .collect();

    // Sort by id to ensure ascending order
    response_items.sort_by_key(|item| item.id);

    info!(
        max = q.max,
        lease_ms = q.lease_ms,
        claimed = response_items.len(),
        "traffic claim"
    );

    Ok(Json(response_items))
}

/// Acknowledge traffic audit events and remove them from the queue
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "AckTrafficEvents",
    tag = "Traffic", 
    path = "/jet/traffic/ack",
    request_body(content = AckRequest, description = "Array of event IDs to acknowledge", content_type = "application/json"),
    responses(
        (status = 200, description = "Successfully acknowledged events", body = AckResponse),
        (status = 400, description = "Invalid request body (empty ids array)"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 413, description = "Payload too large (more than 10,000 IDs)"),
        (status = 500, description = "Internal server error"),
    ),
    security(("scope_token" = ["gateway.traffic.ack"])),
))]
pub async fn post_traffic_ack(
    _scope: TrafficAckScope,
    State(state): State<crate::DgwState>,
    Json(req): Json<AckRequest>,
) -> Result<Json<AckResponse>, HttpError> {
    if req.ids.is_empty() {
        return Err(HttpError::bad_request().msg("ids array cannot be empty"));
    }

    if req.ids.len() > 10_000 {
        return Err(
            HttpErrorBuilder::new(axum::http::StatusCode::PAYLOAD_TOO_LARGE).msg("ids array too large (max 10000)")
        );
    }

    let handle = &state.traffic_audit_handle;

    let deleted_count = handle.ack(req.ids.clone()).await.map_err(HttpError::internal().err())?;

    info!(deleted = deleted_count, "traffic ack");

    Ok(Json(AckResponse { deleted_count }))
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
pub struct ClaimQuery {
    /// Lease duration in milliseconds (1000-3600000, default: 300000 = 5 minutes)
    #[serde(default = "default_lease_ms")]
    pub lease_ms: u32,
    /// Maximum number of events to claim (1-1000, default: 100)
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_lease_ms() -> u32 {
    1000 * 60 * 5 // 5 minutes
}

fn default_max() -> usize {
    100
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
pub struct AckRequest {
    /// Array of event IDs to acknowledge (1-10000 items)
    pub ids: Vec<i64>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
pub struct AckResponse {
    /// Number of events that were acknowledged and deleted
    pub deleted_count: u64,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
pub struct ClaimedTrafficEvent {
    /// Database ID of the claimed event (used for acknowledgment)
    pub id: i64,
    /// Traffic event data
    #[serde(flatten)]
    pub event: TrafficEventResponse,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
pub struct TrafficEventResponse {
    /// Unique identifier for the session/tunnel this traffic item belongs to
    pub session_id: Uuid,
    /// Classification of how the traffic item lifecycle ended
    pub outcome: EventOutcomeResponse,
    /// Transport protocol used for the connection attempt
    pub protocol: TransportProtocolResponse,
    /// Original target host string before DNS resolution
    pub target_host: String,
    /// Concrete target IP address after resolution
    pub target_ip: IpAddr,
    /// Target port number for the connection
    pub target_port: u16,
    /// Timestamp when the connection attempt began (epoch milliseconds)
    pub connect_at_ms: i64,
    /// Timestamp when the traffic item was closed or connection failed (epoch milliseconds)
    pub disconnect_at_ms: i64,
    /// Total duration the traffic item was active (milliseconds)
    pub active_duration_ms: i64,
    /// Total bytes transmitted to the remote peer
    pub bytes_tx: u64,
    /// Total bytes received from the remote peer
    pub bytes_rx: u64,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcomeResponse {
    /// Could not establish a transport to a concrete socket address
    ConnectFailure,
    /// Data path was established and the traffic item ended cleanly
    NormalTermination,
    /// Data path was established but the traffic item ended with an error
    AbnormalTermination,
}

impl From<EventOutcome> for EventOutcomeResponse {
    fn from(outcome: EventOutcome) -> Self {
        match outcome {
            EventOutcome::ConnectFailure => Self::ConnectFailure,
            EventOutcome::NormalTermination => Self::NormalTermination,
            EventOutcome::AbnormalTermination => Self::AbnormalTermination,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocolResponse {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol  
    Udp,
}

impl From<TransportProtocol> for TransportProtocolResponse {
    fn from(protocol: TransportProtocol) -> Self {
        match protocol {
            TransportProtocol::Tcp => Self::Tcp,
            TransportProtocol::Udp => Self::Udp,
        }
    }
}

impl From<TrafficEvent> for TrafficEventResponse {
    fn from(event: TrafficEvent) -> Self {
        Self {
            session_id: event.session_id,
            outcome: event.outcome.into(),
            protocol: event.protocol.into(),
            target_host: event.target_host,
            target_ip: event.target_ip,
            target_port: event.target_port,
            connect_at_ms: event.connect_at_ms,
            disconnect_at_ms: event.disconnect_at_ms,
            active_duration_ms: event.active_duration_ms,
            bytes_tx: event.bytes_tx,
            bytes_rx: event.bytes_rx,
        }
    }
}
