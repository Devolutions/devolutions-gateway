use crate::DgwState;
use crate::http::HttpError;
use axum::{Json, Router, extract, routing};
use network_monitor;
use time::OffsetDateTime;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    let router = Router::new()
        .route("/config", routing::post(handle_set_monitoring_config))
        .route("/log/drain", routing::post(handle_drain_log));

    router.with_state(state)
}

/// Replaces the existing monitoring config with the one provided in the body.
/// This request will immediately start any new monitors, and will stop
/// currently active monitors that are no longer in the config.
///
/// The configuration is not persisted across restarts.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "SetMonitoringConfig",
    tag = "NetworkMonitoring",
    path = "/jet/net/monitor//config",
    request_body(content = MonitorsConfig, description = "JSON object containing a list of monitors", content_type = "application/json"),
    responses(
        (status = 200, description = "New configuration was accepted"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error while starting monitors"),
    ),
))]
async fn handle_set_monitoring_config(
    extract::State(DgwState { monitoring_state, .. }): extract::State<DgwState>,
    Json(config): Json<MonitorsConfig>,
) -> Result<Json<SetConfigResponse>, HttpError> {
    let (processed_config, probe_type_errors) = config.lossy_into();

    network_monitor::set_config(processed_config, monitoring_state)
        .await
        .map(|_| Json(SetConfigResponse::new(probe_type_errors)))
        .map_err(
            HttpError::internal()
                .with_msg("Failed to set up network monitoring")
                .err(),
        )
}

/// Monitors store their results in a temporary log, which is returned here.
/// Once the log is downloaded, gateway purges it from memory.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "DrainMonitoringLog",
    tag = "NetworkMonitoring",
    path = "/jet/net/monitor/log/drain",
    responses(
        (status = 200, description = "Log was flushed and returned in the response body", body = MonitoringLogResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
))]
async fn handle_drain_log(
    extract::State(DgwState { monitoring_state, .. }): extract::State<DgwState>,
) -> Json<MonitoringLogResponse> {
    Json(MonitoringLogResponse {
        entries: network_monitor::drain_log(monitoring_state)
            .into_iter()
            .map(MonitorResult::from)
            .collect(),
    })
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorsConfig {
    monitors: Vec<MonitorDefinition>,
}

impl MonitorsConfig {
    fn lossy_into(self) -> (network_monitor::MonitorsConfig, Vec<MonitorDefinitionProbeTypeError>) {
        let (monitors, errors): (
            Vec<network_monitor::MonitorDefinition>,
            Vec<MonitorDefinitionProbeTypeError>,
        ) = self.monitors.into_iter().map(MonitorDefinition::try_into).fold(
            (
                Vec::<network_monitor::MonitorDefinition>::new(),
                Vec::<MonitorDefinitionProbeTypeError>::new(),
            ),
            |mut partitions, conversion_result| {
                match conversion_result {
                    Ok(value) => partitions.0.push(value),
                    Err(error) => partitions.1.push(error),
                };

                return partitions;
            },
        );

        let config = network_monitor::MonitorsConfig { monitors: monitors };

        return (config, errors);
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Eq, PartialEq, Hash, Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum MonitoringProbeType {
    Ping,
    TcpOpen,
    #[serde(untagged)]
    Unknown(String),
}
pub struct MonitoringProbeTypeError {
    probe: String,
}

impl TryFrom<MonitoringProbeType> for network_monitor::ProbeType {
    type Error = MonitoringProbeTypeError;

    fn try_from(value: MonitoringProbeType) -> Result<network_monitor::ProbeType, Self::Error> {
        match value {
            MonitoringProbeType::Ping => Ok(network_monitor::ProbeType::Ping),
            MonitoringProbeType::TcpOpen => Ok(network_monitor::ProbeType::TcpOpen),
            MonitoringProbeType::Unknown(unknown_type) => Err(MonitoringProbeTypeError { probe: unknown_type }),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Eq, PartialEq, Hash, Clone, Serialize, Deserialize, Debug)]
pub struct MonitorDefinition {
    id: String,
    probe: MonitoringProbeType,
    address: String,
    interval: u64,
    timeout: u64,
    port: Option<i16>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
pub struct MonitorDefinitionProbeTypeError {
    /// The ID of the monitor definition in the client-provided config
    id: String,
    /// The monitor type that was not supported
    probe: String,
}

impl TryFrom<MonitorDefinition> for network_monitor::MonitorDefinition {
    type Error = MonitorDefinitionProbeTypeError;

    fn try_from(value: MonitorDefinition) -> Result<network_monitor::MonitorDefinition, Self::Error> {
        Ok(network_monitor::MonitorDefinition {
            id: value.id.clone(),
            probe: value.probe.try_into().map_err(|type_error: MonitoringProbeTypeError| {
                MonitorDefinitionProbeTypeError {
                    id: value.id.clone(),
                    probe: type_error.probe,
                }
            })?,
            address: value.address,
            interval: value.interval,
            timeout: value.timeout,
            port: value.port,
        })
    }
}

/// This body is returned when the config is successfully set, even if one or all probes were not understood.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[derive(Debug, Clone, Serialize)]
struct SetConfigResponse {
    /// An optional list of probes that this server could not parse.
    probe_type_errors: Option<Vec<MonitorDefinitionProbeTypeError>>,
}

impl SetConfigResponse {
    fn new(probe_type_errors: Vec<MonitorDefinitionProbeTypeError>) -> SetConfigResponse {
        match probe_type_errors.is_empty() {
            false => SetConfigResponse {
                probe_type_errors: Some(probe_type_errors),
            },
            true => SetConfigResponse {
                probe_type_errors: None,
            },
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
pub(crate) struct MonitoringLogResponse {
    entries: Vec<MonitorResult>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub struct MonitorResult {
    monitor_id: String,
    #[serde(with = "time::serde::rfc3339")]
    request_start_time: OffsetDateTime,
    response_success: bool,
    response_messages: Option<String>,
    response_time: f64,
}

impl From<network_monitor::MonitorResult> for MonitorResult {
    fn from(value: network_monitor::MonitorResult) -> Self {
        MonitorResult {
            monitor_id: value.monitor_id,
            request_start_time: value.request_start_time.into(),
            response_success: value.response_success,
            response_messages: value.response_messages,
            response_time: value.response_time,
        }
    }
}
