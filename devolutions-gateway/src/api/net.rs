use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use axum::extract::WebSocketUpgrade;
use axum::extract::ws::{Message, Utf8Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use network_scanner::event_bus::AnyScannerEvent;
use network_scanner::interfaces;
use network_scanner::ip_utils::IpAddrRange;
use network_scanner::named_port::MaybeNamedPort;
use network_scanner::planner::{
    DEFAULT_MAX_TARGET_RANGE_ADDRESSES, InterfaceSelector, NetworkScanPlanError, RangeInterfacePolicy, TargetSelector,
};
use network_scanner::results::{NetworkScanResponseFormat, ScanEventFilter};
use network_scanner::scanner::{self, NetworkScannerParams, ScannerConfig};
use network_scanner::sources::{ScannerSource, ScannerSourceCapabilities};
use serde::{Deserialize, Serialize};

use crate::DgwState;
use crate::extract::RepeatQuery;
use crate::http::HttpError;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    let router = Router::new()
        .route("/scan", axum::routing::get(handle_network_scan))
        .route("/config", axum::routing::get(get_net_config))
        .route("/interfaces", axum::routing::get(get_net_interfaces));

    router.with_state(state)
}

/// Stream network scan events over a websocket.
///
/// The endpoint is upgraded from HTTP, so OpenAPI describes the **handshake**:
/// the query parameters that drive the scan (validated before upgrade) and
/// the legacy / v1 event payloads streamed back as JSON text frames. See
/// `NetworkScanResultEvent` for the v1 shape and `LegacyScanEvent` for the
/// legacy shape (selected via `response_format`).
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetNetScan",
    tag = "Net",
    path = "/jet/net/scan",
    params(NetworkScanQueryParams),
    responses(
        (status = 101, description = "WebSocket upgrade; subsequent text frames carry NetworkScanResultEvent or LegacyScanEvent JSON"),
        (status = 400, description = "Invalid query, mixed target/range, oversized range, or selected interface error"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("netscan_token" = [])),
))]
pub async fn handle_network_scan(
    _token: crate::extract::NetScanToken,
    ws: WebSocketUpgrade,
    RepeatQuery(query): RepeatQuery<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    let (scanner_params, filter) = match <(NetworkScannerParams, ScanEventFilter)>::try_from(query) {
        Ok(x) => x,
        Err(error) => return Ok(query_validation_error_response(error)),
    };

    let scanner = match scanner::NetworkScanner::new(scanner_params) {
        Ok(scanner) => scanner,
        Err(error) => match error.downcast::<NetworkScanPlanError>() {
            Ok(error) => return Ok(network_scan_plan_error_response(error)),
            Err(error) => {
                error!(error = format!("{error:#}"), "Failed to create network scanner");
                return Err(HttpError::internal().build(error));
            }
        },
    };

    let res = ws.on_upgrade(move |mut websocket| async move {
        let stream = match scanner.start() {
            Ok(stream) => stream,
            Err(e) => {
                error!(error = format!("{e:#}"), "Failed to start network scan");
                return;
            }
        };

        info!("Network scan started");

        let mut receiver = stream.subscribe::<AnyScannerEvent>().await;
        // `max_wait_time` cancels the internal scan tasks but doesn't drop
        // the broadcast `Sender`, so a naive `receiver.recv()` would never
        // observe `Closed`. The scanner exposes a `Notify` that fires when
        // the watchdog (or an explicit `stream.stop()`) declares the scan
        // finished — race against it so we can close 1000 cleanly.
        let finished = stream.finished();

        loop {
            tokio::select! {
                _ = finished.notified() => {
                    let _ = websocket
                        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                            code: axum::extract::ws::close_code::NORMAL,
                            reason: Utf8Bytes::from_static("network scan finished (max_wait reached)"),
                        })))
                        .await;
                    break;
                },
                result = receiver.recv() => {
                    let Ok(event) = result else {
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: Utf8Bytes::from_static("network scan finished successfully"),
                            })))
                            .await;

                        break;
                    };

                    let Some(response) = filter.serialize_event(event.0, stream.sources()) else {
                        continue;
                    };

                    if let Err(error) = websocket.send(Message::Text(Utf8Bytes::from(response))).await {
                        warn!(%error, "Failed to send message");

                        // It is very likely that the websocket is already closed, but send it as a precaution.
                        let _ = websocket
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::ABNORMAL,
                                reason: Utf8Bytes::from_static("network scan finished prematurely."),
                            })))
                            .await;

                        break;
                    }
                },
                msg = websocket.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };

                    if let Ok(Message::Close(_)) = msg {
                        break;
                    }
                }
            }
        }

        // Stop the network scanner, whatever the code path (error or not).
        stream.stop();

        // In case the websocket is not closed yet.
        // If the logic above is correct, it’s not necessary.
        let _ = futures::SinkExt::close(&mut websocket).await;

        info!("Network scan finished");
    });

    Ok(res)
}

#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[derive(Debug, Deserialize)]
pub struct NetworkScanQueryParams {
    /// Interval in milliseconds (default is 200)
    pub ping_interval: Option<u64>,
    /// Timeout in milliseconds (default is 500)
    pub ping_timeout: Option<u64>,
    /// Timeout in milliseconds (default is 1000)
    pub broadcast_timeout: Option<u64>,
    /// Timeout in milliseconds (default is 1000)
    pub port_scan_timeout: Option<u64>,
    /// Timeout in milliseconds (default is 1000)
    pub netbios_timeout: Option<u64>,
    /// Interval in milliseconds (default is 200)
    pub netbios_interval: Option<u64>,
    /// The maximum time for each mdns query in milliseconds. (default is 5 * 1000)
    pub mdns_query_timeout: Option<u64>,
    /// The maximum duration for whole networking scan in milliseconds. Highly suggested!
    pub max_wait: Option<u64>,
    /// The start and end IP address of the range to scan.
    /// for example: 10.10.0.0-10.10.0.255
    #[serde(default, rename = "range")]
    pub ranges: Vec<String>,
    /// Explicit single-host targets to scan.
    #[serde(default, rename = "target")]
    pub targets: Vec<IpAddr>,
    /// Gateway network interface IDs to use as scan sources.
    #[serde(default, rename = "interface_id")]
    pub interface_ids: Vec<String>,
    /// The probes to run. Each value is either `ping`, a port number
    /// (`22`), or a named service (`rdp`, `https`, …). Validation is
    /// deferred to scan-time so failures can be surfaced as a structured
    /// 400 — naming the offending value — instead of a generic serde
    /// rejection at extraction time.
    #[serde(default, rename = "probe")]
    pub probes: Vec<String>,

    /// **Legacy alias** for `report_ping_start`. Prefer the explicit name in
    /// new clients; kept for backward compatibility per plan §"Compatibility
    /// strategy".
    #[deprecated(note = "see field doc comment for the new parameter name")]
    #[serde(default)]
    pub enable_ping_start: bool,

    /// Enable the execution of broadcast scan
    #[serde(default = "default_true")]
    pub enable_broadcast: bool,

    /// Enable the ping scan on subnet
    #[serde(default = "default_true")]
    pub enable_subnet_scan: bool,

    /// Enable ZeroConf/mDNS
    #[serde(default = "default_true")]
    pub enable_zeroconf: bool,

    /// Enable NetBIOS name-service queries. Default `true` for backward
    /// compatibility. Set `false` (or pair with explicit `target=`) to
    /// keep NetBIOS from sweeping the surrounding subnet when the caller
    /// only wants results for the targets they listed.
    #[serde(default = "default_true")]
    pub enable_netbios: bool,

    /// Enable resolve dns
    #[serde(default = "default_true")]
    pub enable_resolve_dns: bool,

    /// Include host-only results.
    #[serde(default = "default_true")]
    pub include_host_results: bool,

    /// Emit ping status events.
    #[serde(default)]
    pub report_ping_status: bool,

    /// Emit ping queued/start host results.
    #[serde(default)]
    pub report_ping_start: bool,

    /// Emit ping success host results.
    #[serde(default)]
    pub report_ping_success: bool,

    /// Emit ping failure host results.
    #[serde(default)]
    pub report_ping_failure: bool,

    /// Enable TCP service probes.
    #[serde(default = "default_true")]
    pub enable_tcp_probes: bool,

    /// Policy applied when range and interface_id are both provided.
    pub range_interface_policy: Option<RangeInterfacePolicy>,

    /// **Legacy alias** for `range_interface_policy=allow_cross_interface_range`.
    /// Prefer the structured policy in new clients.
    #[deprecated(note = "see field doc comment for the new parameter name")]
    #[serde(default)]
    pub allow_cross_interface_range: bool,

    /// Response shape emitted on the websocket.
    pub response_format: Option<NetworkScanResponseFormat>,

    /// Maximum scanner concurrency.
    pub max_concurrency: Option<usize>,

    /// Maximum ping probe concurrency.
    pub max_ping_concurrency: Option<usize>,

    /// Maximum TCP probe concurrency.
    pub max_tcp_probe_concurrency: Option<usize>,

    /// **Legacy alias** for `report_tcp_failure`. Per plan §4, `enable_failure`
    /// remains for failed TCP probes only; new clients should use the explicit
    /// `report_tcp_failure` parameter.
    #[deprecated(note = "see field doc comment for the new parameter name")]
    #[serde(default)]
    pub enable_failure: bool,

    /// Enable TCP port knocking failure events.
    #[serde(default)]
    pub report_tcp_failure: bool,

    /// When `true`, fail with HTTP 400 if a ping/TCP-probe socket cannot be
    /// bound to the planner-selected interface. Default `false` (warn and
    /// fall back to default routing).
    #[serde(default)]
    pub interface_bind_strict: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkScanPlanErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ranges: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_ids: Option<Vec<String>>,
}

fn network_scan_plan_error_response(error: NetworkScanPlanError) -> Response {
    match error {
        NetworkScanPlanError::InvalidInterface(error) => {
            let body = NetworkScanPlanErrorResponse {
                error: "invalid_network_scan_interface",
                interface_id: Some(error.interface_id().to_owned()),
                reason: Some(error.reason()),
                ranges: None,
                interface_ids: None,
            };
            (StatusCode::BAD_REQUEST, Json(body)).into_response()
        }
        NetworkScanPlanError::RangeOutsideSelectedInterfaces { ranges, interface_ids } => {
            let body = NetworkScanPlanErrorResponse {
                error: "range_outside_selected_interfaces",
                interface_id: None,
                reason: None,
                ranges: Some(ranges),
                interface_ids: Some(interface_ids),
            };
            (StatusCode::BAD_REQUEST, Json(body)).into_response()
        }
    }
}

/// Result of parsing a single `probe=` query value.
enum ParsedProbe {
    Ping,
    Port(MaybeNamedPort),
}

fn parse_probe(raw: &str) -> Result<ParsedProbe, ()> {
    if raw.eq_ignore_ascii_case("ping") {
        Ok(ParsedProbe::Ping)
    } else {
        MaybeNamedPort::try_from(raw).map(ParsedProbe::Port).map_err(|_| ())
    }
}

const COMMON_PORTS: [u16; 11] = [22, 23, 80, 443, 389, 636, 3283, 3389, 5900, 5985, 5986];

/// Structured rejection codes for `/jet/net/scan` query validation.
///
/// Each variant maps 1-to-1 to a stable `error` string in the JSON 400
/// body so callers can branch on the cause without parsing prose.
#[derive(Debug)]
pub enum NetworkScanQueryError {
    /// The combined `target` + `range` selector spans both IPv4 and IPv6.
    MixedIpFamilies,
    /// A `range` exceeds the configured per-range size cap.
    RangeTooLarge {
        address_count: u128,
        max_range_addresses: u128,
    },
    /// A `probe=<value>` could not be parsed as `ping`, a port, or a named service.
    InvalidProbe { value: String },
    /// A `target=<value>` could not be parsed as an IP address.
    InvalidTarget { value: String },
    /// A `range=<value>` could not be parsed as a `lower-upper` IP range.
    InvalidRange { value: String, message: String },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryValidationErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_count: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_range_addresses: Option<u128>,
}

fn query_validation_error_response(error: NetworkScanQueryError) -> Response {
    let body = match error {
        NetworkScanQueryError::MixedIpFamilies => QueryValidationErrorResponse {
            error: "mixed_ip_families",
            value: None,
            message: None,
            address_count: None,
            max_range_addresses: None,
        },
        NetworkScanQueryError::RangeTooLarge {
            address_count,
            max_range_addresses,
        } => QueryValidationErrorResponse {
            error: "range_too_large",
            value: None,
            message: None,
            address_count: Some(address_count),
            max_range_addresses: Some(max_range_addresses),
        },
        NetworkScanQueryError::InvalidProbe { value } => QueryValidationErrorResponse {
            error: "invalid_probe",
            value: Some(value),
            message: None,
            address_count: None,
            max_range_addresses: None,
        },
        NetworkScanQueryError::InvalidTarget { value } => QueryValidationErrorResponse {
            error: "invalid_target",
            value: Some(value),
            message: None,
            address_count: None,
            max_range_addresses: None,
        },
        NetworkScanQueryError::InvalidRange { value, message } => QueryValidationErrorResponse {
            error: "invalid_range",
            value: Some(value),
            message: Some(message),
            address_count: None,
            max_range_addresses: None,
        },
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

impl TryFrom<NetworkScanQueryParams> for (NetworkScannerParams, ScanEventFilter) {
    type Error = NetworkScanQueryError;
    fn try_from(val: NetworkScanQueryParams) -> Result<Self, Self::Error> {
        debug!(query=?val, "Network scan query parameters");

        // Per protocol spec, `target` and `range` may be combined: explicit
        // single hosts are coerced to one-address ranges and merged with
        // explicit multi-host ranges. Each parse failure is reported with
        // the offending raw value so the 400 body can name it.
        let target_selector = if !val.targets.is_empty() || !val.ranges.is_empty() {
            let mut ranges: Vec<IpAddrRange> = Vec::with_capacity(val.ranges.len() + val.targets.len());
            for raw in &val.ranges {
                let parsed =
                    IpAddrRange::try_from(raw.as_str()).map_err(|err| NetworkScanQueryError::InvalidRange {
                        value: raw.clone(),
                        message: err.to_string(),
                    })?;
                ranges.push(parsed);
            }
            ranges.extend(val.targets.iter().copied().map(IpAddrRange::single));
            TargetSelector::ExplicitRanges(ranges)
        } else {
            TargetSelector::DefaultSubnets
        };
        target_selector
            .validate(DEFAULT_MAX_TARGET_RANGE_ADDRESSES)
            .map_err(|err| match err {
                network_scanner::planner::TargetSelectorValidationError::MixedIpFamilies => {
                    NetworkScanQueryError::MixedIpFamilies
                }
                network_scanner::planner::TargetSelectorValidationError::RangeTooLarge {
                    address_count,
                    max_range_addresses,
                } => NetworkScanQueryError::RangeTooLarge {
                    address_count,
                    max_range_addresses,
                },
            })?;
        let interface_selector = if val.interface_ids.is_empty() {
            InterfaceSelector::AllEligible
        } else {
            InterfaceSelector::Selected(val.interface_ids)
        };
        // Legacy alias `allow_cross_interface_range=true` maps to the
        // structured `range_interface_policy`; explicit reads are
        // narrowly `#[allow(deprecated)]` so the lint still fires for any
        // *other* use of these aliases in the future.
        #[allow(deprecated)]
        let allow_cross_interface_range = val.allow_cross_interface_range;
        let default_range_interface_policy = if allow_cross_interface_range {
            RangeInterfacePolicy::AllowCrossInterfaceRange
        } else {
            RangeInterfacePolicy::IntersectSelectedInterfaces
        };
        let range_interface_policy = val.range_interface_policy.unwrap_or(default_range_interface_policy);
        // Probes are validated *unconditionally* — even when
        // `enable_tcp_probes=false` and the parsed list would be ignored —
        // so a typo always lands in the structured 400 instead of getting
        // silently dropped.
        let mut has_ping_probe = false;
        let mut typed_ports: Vec<MaybeNamedPort> = Vec::with_capacity(val.probes.len());
        for raw in &val.probes {
            match parse_probe(raw) {
                Ok(ParsedProbe::Ping) => has_ping_probe = true,
                Ok(ParsedProbe::Port(port)) => typed_ports.push(port),
                Err(()) => return Err(NetworkScanQueryError::InvalidProbe { value: raw.clone() }),
            }
        }
        let ports: Vec<MaybeNamedPort> = match (val.enable_tcp_probes, typed_ports.is_empty()) {
            (false, _) => Vec::new(),
            (true, true) => COMMON_PORTS.iter().map(|p| (*p).into()).collect(),
            (true, false) => typed_ports,
        };

        #[allow(deprecated)]
        let enable_ping_start = val.enable_ping_start;
        let report_ping_start = val.report_ping_start || enable_ping_start || val.report_ping_status;
        let report_ping_success = val.report_ping_success || val.report_ping_status || has_ping_probe;
        let report_ping_failure = val.report_ping_failure || val.report_ping_status;
        // Plan §4 "enable_failure remains only for failed TCP probes and
        // legacy behavior" — keep it as the legacy alias for
        // `report_tcp_failure` and nothing else.
        #[allow(deprecated)]
        let enable_failure = val.enable_failure;
        let report_tcp_failure = val.report_tcp_failure || enable_failure;

        let ping_interval = Duration::from_millis(val.ping_interval.unwrap_or(200));
        let ping_timeout = Duration::from_millis(val.ping_timeout.unwrap_or(500));
        let broadcast_timeout = Duration::from_millis(val.broadcast_timeout.unwrap_or(1000));
        let port_scan_timeout = Duration::from_millis(val.port_scan_timeout.unwrap_or(1000));
        let netbios_timeout = Duration::from_millis(val.netbios_timeout.unwrap_or(1000));
        let netbios_interval = Duration::from_millis(val.netbios_interval.unwrap_or(200));
        let mdns_query_timeout = Duration::from_millis(val.mdns_query_timeout.unwrap_or(5 * 1000));
        let max_wait_time = Duration::from_millis(val.max_wait.unwrap_or(120 * 1000));
        let scanner_param = NetworkScannerParams {
            config: ScannerConfig {
                ports,
                timing: scanner::TimingConfig {
                    ping_interval,
                    ping_timeout,
                    broadcast_timeout,
                    port_scan_timeout,
                    netbios_timeout,
                    netbios_interval,
                    mdns_query_timeout,
                    max_wait_time,
                },
                limits: scanner::LimitsConfig {
                    max_concurrency: val.max_concurrency,
                    max_ping_concurrency: val.max_ping_concurrency.or(val.max_concurrency),
                    max_tcp_probe_concurrency: val.max_tcp_probe_concurrency.or(val.max_concurrency),
                },
                targeting: scanner::TargetingConfig {
                    target_selector,
                    interface_selector,
                    range_interface_policy,
                    interface_bind_strict: val.interface_bind_strict,
                },
            },
            toggle: scanner::ScannerToggles {
                enable_broadcast: val.enable_broadcast,
                enable_subnet_scan: val.enable_subnet_scan,
                enable_zeroconf: val.enable_zeroconf,
                enable_resolve_dns: val.enable_resolve_dns,
                enable_netbios: val.enable_netbios,
            },
        };

        let event_filter = ScanEventFilter::new(network_scanner::results::ScanEventFilterConfig {
            report_ping_start,
            report_ping_success,
            report_ping_failure,
            report_tcp_failure,
            include_host_results: val.include_host_results,
            response_format: val.response_format.unwrap_or_default(),
        });

        Ok((scanner_param, event_filter))
    }
}

/// Lists network interfaces
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetNetConfig",
    tag = "Net",
    path = "/jet/net/config",
    responses(
        (status = 200, description = "Network interfaces", body = [HashMap<String, Vec<InterfaceInfo>>]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("netscan_token" = [])),
))]
pub(crate) async fn get_net_config(_token: crate::extract::NetScanToken) -> Result<Response, HttpError> {
    let net_ifaces = interfaces::get_network_interfaces()
        .map_err(HttpError::internal().with_msg("failed to get network interfaces").err())?;

    let mut interface_map = HashMap::new();

    for iface in net_ifaces {
        let addresses: Vec<InterfaceInfo> = iface
            .addr
            .into_iter()
            .map(|addr| match addr {
                interfaces::Addr::V4(addr) => InterfaceInfo {
                    address: IfAddress::V4 {
                        address: addr.ip,
                        broadcast: addr.broadcast,
                        netmask: addr.netmask,
                    },
                    mac: iface.mac_addr.clone(),
                },
                interfaces::Addr::V6(addr) => InterfaceInfo {
                    address: IfAddress::V6 {
                        address: addr.ip,
                        broadcast: addr.broadcast,
                        netmask: addr.netmask,
                    },
                    mac: iface.mac_addr.clone(),
                },
            })
            .collect();

        interface_map.insert(iface.name, addresses);
    }

    let mut response = Json(interface_map).into_response();
    let headers = response.headers_mut();
    // RFC 8594 — emit `Deprecation: true` plus the `successor-version` /
    // `deprecation` `Link` rels. `Sunset` is intentionally omitted until
    // product confirms a removal milestone; clients only need the
    // `Deprecation` flag and the successor pointer to start migrating.
    headers.insert("Deprecation", axum::http::HeaderValue::from_static("true"));
    headers.insert(
        "Link",
        axum::http::HeaderValue::from_static(
            "</jet/net/interfaces>; rel=\"successor-version\", </jet/net/interfaces>; rel=\"deprecation\"",
        ),
    );
    Ok(response)
}

/// Lists Gateway network scan sources.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetNetInterfaces",
    tag = "Net",
    path = "/jet/net/interfaces",
    responses(
        (status = 200, description = "Gateway network scan sources", body = NetworkInterfacesResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("netscan_token" = [])),
))]
pub(crate) async fn get_net_interfaces(
    _token: crate::extract::NetScanToken,
) -> Result<Json<NetworkInterfacesResponse>, HttpError> {
    let sources = network_scanner::sources::get_system_sources().map_err(
        HttpError::internal()
            .with_msg("failed to get network scan sources")
            .err(),
    )?;

    Ok(Json(NetworkInterfacesResponse::from_sources(sources)))
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkInterfacesResponse {
    interfaces: Vec<NetworkScanSourceDto>,
}

impl NetworkInterfacesResponse {
    fn from_sources(sources: Vec<ScannerSource>) -> Self {
        Self {
            interfaces: sources.into_iter().map(NetworkScanSourceDto::from).collect(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkScanSourceDto {
    interface: NetworkInterfaceDto,
    address: String,
    start_address: String,
    end_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix_length: Option<u8>,
    capabilities: NetworkScanSourceCapabilitiesDto,
}

impl From<ScannerSource> for NetworkScanSourceDto {
    fn from(source: ScannerSource) -> Self {
        let link_type = source.link_type.as_str();
        Self {
            interface: NetworkInterfaceDto {
                id: source.interface_id,
                name: source.interface_name,
                description: source.interface_description,
                index: source.interface_index,
                mac_address: source.mac_address,
                is_up: source.is_up,
                mtu: source.mtu,
                speed_mbps: source.speed_mbps,
                link_type: Some(link_type.to_owned()),
            },
            address: source.address.to_string(),
            start_address: source.start_address.to_string(),
            end_address: source.end_address.to_string(),
            broadcast_address: source.broadcast_address.map(|address| address.to_string()),
            prefix_length: source.prefix_length,
            capabilities: source.capabilities.into(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkInterfaceDto {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_up: Option<bool>,
    /// MTU in bytes when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,
    /// Link speed in megabits per second when reported by the OS.
    #[serde(skip_serializing_if = "Option::is_none")]
    speed_mbps: Option<u64>,
    /// Coarse link type: `ethernet`, `wifi`, `loopback`, `virtual`, `unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    link_type: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkScanSourceCapabilitiesDto {
    ipv4: bool,
    ipv6: bool,
    subnet: bool,
    broadcast: bool,
    zero_conf: bool,
    tcp_probe: bool,
    dns_resolve: bool,
}

impl From<ScannerSourceCapabilities> for NetworkScanSourceCapabilitiesDto {
    fn from(capabilities: ScannerSourceCapabilities) -> Self {
        Self {
            ipv4: capabilities.ipv4,
            ipv6: capabilities.ipv6,
            subnet: capabilities.subnet,
            broadcast: capabilities.broadcast,
            zero_conf: capabilities.zeroconf,
            tcp_probe: capabilities.tcp_probe,
            dns_resolve: capabilities.dns_resolve,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InterfaceInfo {
    #[serde(flatten)]
    address: IfAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "family")]
enum IfAddress {
    #[serde(rename = "IPv4")]
    V4 {
        address: Ipv4Addr,
        #[serde(skip_serializing_if = "Option::is_none")]
        broadcast: Option<Ipv4Addr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        netmask: Option<Ipv4Addr>,
    },
    #[serde(rename = "IPv6")]
    V6 {
        address: Ipv6Addr,
        #[serde(skip_serializing_if = "Option::is_none")]
        broadcast: Option<Ipv6Addr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        netmask: Option<Ipv6Addr>,
    },
}

// ---------------------------------------------------------------------------
// Schema-only DTOs for the V1 wire shape.
//
// `network-scanner` deliberately doesn't depend on `utoipa` (it's a generic
// scanner library, not the gateway's HTTP layer). To still surface the
// `/jet/net/scan` event payload in the gateway's OpenAPI document, we mirror
// the runtime types here as gateway-local DTOs whose only job is to carry
// `ToSchema` derives. They're never constructed at runtime.
//
// If `network_scanner::results::NetworkScanResultEvent` ever changes its wire
// shape, update these mirrors in the same PR.
// ---------------------------------------------------------------------------

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[allow(dead_code)] // schema-only — see module comment above.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkScanResultKindDto {
    Host,
    Service,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanResultSourceDto {
    Subnet,
    Broadcast,
    TcpProbe,
    Gateway,
    ZeroConf,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanOriginDto {
    Gateway,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HostScanStateDto {
    Queued,
    Probing,
    Reachable,
    Unreachable,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkScanResultEventDto {
    kind: NetworkScanResultKindDto,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_name: Option<String>,
    source: ScanOriginDto,
    discovery_source: ScanResultSourceDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_reachable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_scan_state: Option<HostScanStateDto>,
    response_time_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_address: Option<String>,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_mapping_accepts_explicit_targets() {
        let (scanner_params, filter) = NetworkScanQueryParams {
            targets: vec![
                "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                "192.168.1.20".parse().expect("fixture IPv4 address should parse"),
            ],
            ..minimal_query()
        }
        .try_into()
        .expect("explicit target query should map to scanner params");

        // Two `target` params coerce to two single-address ranges (plan
        // §1: "target is equivalent to a one-address range").
        assert!(matches!(
            scanner_params.config.targeting.target_selector,
            TargetSelector::ExplicitRanges(ref ranges) if ranges.len() == 2
        ));
        assert_eq!(
            scanner_params.config.targeting.interface_selector,
            InterfaceSelector::AllEligible
        );
        assert!(scanner_params.toggle.enable_broadcast);
        assert!(scanner_params.toggle.enable_zeroconf);
        assert!(filter.enable_ping_event());
    }

    #[test]
    fn query_mapping_combines_targets_and_ranges() {
        let (scanner_params, _) = NetworkScanQueryParams {
            targets: vec!["192.168.1.10".parse().expect("fixture IPv4 address should parse")],
            ranges: vec!["192.168.2.0-192.168.2.10".to_owned()],
            ..minimal_query()
        }
        .try_into()
        .expect("plan §1 says target and range can be combined");

        match scanner_params.config.targeting.target_selector {
            TargetSelector::ExplicitRanges(ranges) => {
                // First the multi-host range, then the coerced single-host range.
                assert_eq!(ranges.len(), 2);
            }
            other => panic!("expected ExplicitRanges, got {other:?}"),
        }
    }

    #[test]
    fn query_mapping_accepts_selected_interface_ids() {
        let (scanner_params, _) = NetworkScanQueryParams {
            interface_ids: vec!["eth0".to_owned(), "wifi0".to_owned()],
            ..minimal_query()
        }
        .try_into()
        .expect("interface query should map to scanner params");

        assert_eq!(
            scanner_params.config.targeting.interface_selector,
            InterfaceSelector::Selected(vec!["eth0".to_owned(), "wifi0".to_owned()])
        );
        assert_eq!(
            scanner_params.config.targeting.target_selector,
            TargetSelector::DefaultSubnets
        );
    }

    #[test]
    fn query_mapping_disables_tcp_probes() {
        let (scanner_params, _) = NetworkScanQueryParams {
            enable_tcp_probes: false,
            probes: vec!["3389".to_owned()],
            ..minimal_query()
        }
        .try_into()
        .expect("TCP probe query should map to scanner params");

        assert!(scanner_params.config.ports.is_empty());
    }

    #[test]
    fn query_mapping_probe_ping_implicitly_enables_ping_success_events() {
        // Plan §4: `probe=ping` should be sufficient to receive ping events
        // even when the explicit `report_ping_*` toggles are off. Locks the
        // `has_ping_probe` auto-enable branch in `try_from`, which the
        // boolean-toggle permutation test does not exercise (it always
        // ships an empty `probes` list).
        let (_, filter) = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            probes: vec!["ping".to_owned()],
            report_ping_success: false,
            report_ping_status: false,
            ..minimal_query()
        })
        .expect("probe=ping query should map to scanner params");

        assert!(
            filter.report_ping_success(),
            "probe=ping must implicitly enable ping success events even with report_ping_success=false"
        );
    }

    #[test]
    fn query_mapping_accepts_max_concurrency() {
        let (scanner_params, _) = NetworkScanQueryParams {
            max_concurrency: Some(16),
            ..minimal_query()
        }
        .try_into()
        .expect("max concurrency query should map to scanner params");

        assert_eq!(scanner_params.config.limits.max_concurrency, Some(16));
        assert_eq!(scanner_params.config.limits.max_ping_concurrency, Some(16));
        assert_eq!(scanner_params.config.limits.max_tcp_probe_concurrency, Some(16));
    }

    #[test]
    fn query_mapping_accepts_split_probe_concurrency() {
        let (scanner_params, _) = NetworkScanQueryParams {
            max_concurrency: Some(16),
            max_ping_concurrency: Some(4),
            max_tcp_probe_concurrency: Some(8),
            ..minimal_query()
        }
        .try_into()
        .expect("split concurrency query should map to scanner params");

        assert_eq!(scanner_params.config.limits.max_concurrency, Some(16));
        assert_eq!(scanner_params.config.limits.max_ping_concurrency, Some(4));
        assert_eq!(scanner_params.config.limits.max_tcp_probe_concurrency, Some(8));
    }

    #[test]
    #[allow(deprecated)]
    fn query_mapping_accepts_range_with_interface_and_cross_interface_policy() {
        let (scanner_params, _) = NetworkScanQueryParams {
            ranges: vec!["192.168.1.1-192.168.1.20".to_owned()],
            interface_ids: vec!["eth0".to_owned()],
            allow_cross_interface_range: true,
            ..minimal_query()
        }
        .try_into()
        .expect("range plus interface query should map to scanner params");

        assert!(matches!(
            scanner_params.config.targeting.target_selector,
            TargetSelector::ExplicitRanges(ref ranges) if ranges.len() == 1
        ));
        assert_eq!(
            scanner_params.config.targeting.interface_selector,
            InterfaceSelector::Selected(vec!["eth0".to_owned()])
        );
        assert_eq!(
            scanner_params.config.targeting.range_interface_policy,
            RangeInterfacePolicy::AllowCrossInterfaceRange
        );
    }

    #[test]
    fn query_mapping_rejects_mixed_ip_family_targets_with_ranges() {
        // The combined target/range path still validates IP family
        // consistency: an IPv4 target plus an IPv6 range must error.
        let error = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            targets: vec!["192.168.1.10".parse().expect("fixture IPv4 address should parse")],
            ranges: vec!["fd00::1-fd00::2".to_owned()],
            ..minimal_query()
        })
        .expect_err("mixed IP families across target and range should be rejected");

        assert!(matches!(error, NetworkScanQueryError::MixedIpFamilies));
    }

    #[test]
    #[allow(deprecated)]
    fn query_mapping_enable_failure_is_legacy_alias_for_report_tcp_failure() {
        // Plan §4 + Compatibility strategy: `enable_failure` is the legacy
        // toggle for TCP-probe failures. It must NOT trigger ping failures.
        let (_, filter) = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            enable_failure: true,
            ..minimal_query()
        })
        .expect("enable_failure query should map to scanner params");

        assert!(
            filter.report_tcp_failure(),
            "enable_failure=true must activate TCP-probe failure reporting (legacy semantics)"
        );
        assert!(
            !filter.report_ping_failure(),
            "enable_failure=true must NOT silently activate ping-failure reporting"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn query_mapping_report_tcp_failure_works_without_enable_failure() {
        let (_, filter) = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            enable_failure: false,
            report_tcp_failure: true,
            ..minimal_query()
        })
        .expect("report_tcp_failure query should map to scanner params");

        assert!(filter.report_tcp_failure());
        assert!(!filter.report_ping_failure());
    }

    #[test]
    fn query_mapping_rejects_mixed_ip_family_targets() {
        let error = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            targets: vec![
                "192.168.1.10".parse().expect("fixture IPv4 address should parse"),
                "fd00::10".parse().expect("fixture IPv6 address should parse"),
            ],
            ..minimal_query()
        })
        .expect_err("mixed IP target families should be rejected");

        assert!(matches!(error, NetworkScanQueryError::MixedIpFamilies));
    }

    #[test]
    fn query_mapping_rejects_oversized_ip_ranges() {
        let error = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            ranges: vec!["192.168.0.0-192.169.0.0".to_owned()],
            ..minimal_query()
        })
        .expect_err("oversized IP ranges should be rejected");

        match error {
            NetworkScanQueryError::RangeTooLarge {
                address_count,
                max_range_addresses,
            } => {
                assert_eq!(max_range_addresses, DEFAULT_MAX_TARGET_RANGE_ADDRESSES);
                assert!(address_count > max_range_addresses);
            }
            other => panic!("expected RangeTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn query_mapping_accepts_enable_netbios_toggle() {
        // Plan §1 + §2: explicit `target=` with `enable_netbios=false`
        // must scope the scan to the listed targets without sweeping the
        // surrounding subnet over NetBIOS.
        let (params, _) = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            targets: vec!["10.10.0.1".parse().expect("fixture IPv4 address should parse")],
            enable_netbios: false,
            ..minimal_query()
        })
        .expect("enable_netbios=false should map to scanner params");

        assert!(!params.toggle.enable_netbios);
    }

    #[test]
    fn query_mapping_rejects_invalid_probe_with_named_value() {
        // Plan §6 mandates the 400 body name the offending value so callers
        // can fix their config without scraping prose.
        let error = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            probes: vec!["22".to_owned(), "garbage-value".to_owned()],
            ..minimal_query()
        })
        .expect_err("invalid probe should be rejected");

        match error {
            NetworkScanQueryError::InvalidProbe { value } => assert_eq!(value, "garbage-value"),
            other => panic!("expected InvalidProbe, got {other:?}"),
        }
    }

    #[test]
    fn query_mapping_rejects_invalid_range_with_named_value() {
        let error = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
            ranges: vec!["not-a-range".to_owned()],
            ..minimal_query()
        })
        .expect_err("invalid range should be rejected");

        match error {
            NetworkScanQueryError::InvalidRange { value, .. } => assert_eq!(value, "not-a-range"),
            other => panic!("expected InvalidRange, got {other:?}"),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn query_mapping_covers_boolean_toggle_permutations() {
        for enable_ping_start in [false, true] {
            for enable_broadcast in [false, true] {
                for enable_subnet_scan in [false, true] {
                    for enable_zeroconf in [false, true] {
                        for enable_resolve_dns in [false, true] {
                            for include_host_results in [false, true] {
                                for report_ping_status in [false, true] {
                                    for enable_tcp_probes in [false, true] {
                                        for enable_failure in [false, true] {
                                            for report_ping_start in [false, true] {
                                                for report_ping_success in [false, true] {
                                                    for report_ping_failure in [false, true] {
                                                        for report_tcp_failure in [false, true] {
                                                            for response_format in [
                                                                None,
                                                                Some(NetworkScanResponseFormat::Legacy),
                                                                Some(NetworkScanResponseFormat::NetworkScanResultV1),
                                                            ] {
                                                                let (scanner_params, filter) = NetworkScanQueryParams {
                                                    probes: Vec::new(),
                                                    enable_ping_start,
                                                    enable_broadcast,
                                                    enable_subnet_scan,
                                                    enable_zeroconf,
                                                    enable_resolve_dns,
                                                    include_host_results,
                                                    report_ping_status,
                                                    report_ping_start,
                                                    report_ping_success,
                                                    report_ping_failure,
                                                    enable_tcp_probes,
                                                    enable_failure,
                                                    report_tcp_failure,
                                                    response_format,
                                                    ..minimal_query()
                                                }
                                                .try_into()
                                                .expect("toggle-only query permutation should map to scanner params");

                                                                assert_eq!(
                                                                    scanner_params.toggle.enable_broadcast,
                                                                    enable_broadcast
                                                                );
                                                                assert_eq!(
                                                                    scanner_params.toggle.enable_subnet_scan,
                                                                    enable_subnet_scan
                                                                );
                                                                assert_eq!(
                                                                    scanner_params.toggle.enable_zeroconf,
                                                                    enable_zeroconf
                                                                );
                                                                assert_eq!(
                                                                    scanner_params.toggle.enable_resolve_dns,
                                                                    enable_resolve_dns
                                                                );
                                                                assert_eq!(
                                                                    scanner_params.config.ports.len(),
                                                                    if enable_tcp_probes {
                                                                        COMMON_PORTS.len()
                                                                    } else {
                                                                        0
                                                                    }
                                                                );
                                                                assert_eq!(
                                                                    filter.enable_ping_event(),
                                                                    enable_ping_start
                                                                        || report_ping_start
                                                                        || report_ping_success
                                                                        || report_ping_failure
                                                                        || report_ping_status
                                                                );
                                                                assert_eq!(
                                                                    filter.report_ping_start(),
                                                                    enable_ping_start
                                                                        || report_ping_start
                                                                        || report_ping_status
                                                                );
                                                                assert_eq!(
                                                                    filter.report_ping_success(),
                                                                    report_ping_success || report_ping_status
                                                                );
                                                                assert_eq!(
                                                                    filter.report_ping_failure(),
                                                                    report_ping_failure || report_ping_status
                                                                );
                                                                assert_eq!(
                                                                    filter.report_tcp_failure(),
                                                                    report_tcp_failure || enable_failure
                                                                );
                                                                assert_eq!(
                                                                    filter.include_host_results(),
                                                                    include_host_results
                                                                );
                                                                assert_eq!(
                                                                    filter.response_format(),
                                                                    response_format.unwrap_or_default()
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn query_mapping_covers_target_mode_permutations() {
        for has_targets in [false, true] {
            for has_ranges in [false, true] {
                for has_interface_ids in [false, true] {
                    let result = <(NetworkScannerParams, ScanEventFilter)>::try_from(NetworkScanQueryParams {
                        targets: has_targets
                            .then(|| "192.168.1.10".parse().expect("fixture IPv4 address should parse"))
                            .into_iter()
                            .collect(),
                        ranges: has_ranges
                            .then(|| "192.168.1.20-192.168.1.21".to_owned())
                            .into_iter()
                            .collect(),
                        interface_ids: has_interface_ids.then(|| "eth0".to_owned()).into_iter().collect(),
                        ..minimal_query()
                    });
                    let (scanner_params, _) = result.expect("target mode combination should be accepted");
                    match (
                        &scanner_params.config.targeting.target_selector,
                        has_targets,
                        has_ranges,
                    ) {
                        // Both: target coerced to single-address range, then
                        // appended to the explicit ranges list.
                        (TargetSelector::ExplicitRanges(ranges), true, true) => assert_eq!(ranges.len(), 2),
                        (TargetSelector::ExplicitRanges(ranges), true, false) => assert_eq!(ranges.len(), 1),
                        (TargetSelector::ExplicitRanges(ranges), false, true) => assert_eq!(ranges.len(), 1),
                        (TargetSelector::DefaultSubnets, false, false) => {}
                        _ => panic!("unexpected target selector"),
                    }
                    match (&scanner_params.config.targeting.interface_selector, has_interface_ids) {
                        (InterfaceSelector::Selected(ids), true) => assert_eq!(ids, &vec!["eth0".to_owned()]),
                        (InterfaceSelector::AllEligible, false) => {}
                        _ => panic!("unexpected interface selector"),
                    }
                    assert!(scanner_params.toggle.enable_broadcast);
                    assert!(scanner_params.toggle.enable_zeroconf);
                }
            }
        }
    }

    #[test]
    fn interfaces_response_maps_scanner_sources_to_network_scan_source_shape() {
        let response = NetworkInterfacesResponse::from_sources(vec![ScannerSource {
            interface_id: "eth0|IPv4|192.168.1.25".to_owned(),
            interface_name: "Ethernet (IPv4)".to_owned(),
            interface_description: Some("Intel Ethernet".to_owned()),
            interface_index: Some(12),
            mac_address: Some("00-11-22-33-44-55".to_owned()),
            is_up: Some(true),
            mtu: Some(1500),
            speed_mbps: Some(1000),
            link_type: network_scanner::sources::LinkType::Ethernet,
            address: "192.168.1.25".parse().expect("fixture IPv4 address should parse"),
            start_address: "192.168.1.0".parse().expect("fixture IPv4 address should parse"),
            end_address: "192.168.1.255".parse().expect("fixture IPv4 address should parse"),
            broadcast_address: Some("192.168.1.255".parse().expect("fixture IPv4 address should parse")),
            prefix_length: Some(24),
            capabilities: ScannerSourceCapabilities {
                ipv4: true,
                ipv6: false,
                subnet: true,
                broadcast: true,
                zeroconf: true,
                tcp_probe: true,
                dns_resolve: true,
            },
        }]);

        let value = serde_json::to_value(response).expect("interfaces response should serialize");

        assert_eq!(value["interfaces"][0]["interface"]["id"], "eth0|IPv4|192.168.1.25");
        assert_eq!(value["interfaces"][0]["interface"]["name"], "Ethernet (IPv4)");
        assert_eq!(value["interfaces"][0]["interface"]["macAddress"], "00-11-22-33-44-55");
        assert_eq!(
            value["interfaces"][0]["interface"]["isUp"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(value["interfaces"][0]["address"], "192.168.1.25");
        assert_eq!(value["interfaces"][0]["startAddress"], "192.168.1.0");
        assert_eq!(value["interfaces"][0]["endAddress"], "192.168.1.255");
        assert_eq!(value["interfaces"][0]["broadcastAddress"], "192.168.1.255");
        assert_eq!(value["interfaces"][0]["prefixLength"], 24);
        assert_eq!(
            value["interfaces"][0]["capabilities"]["zeroConf"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            value["interfaces"][0]["capabilities"]["tcpProbe"],
            serde_json::Value::Bool(true)
        );
    }

    #[allow(deprecated)] // Test fixture explicitly populates legacy aliases.
    fn minimal_query() -> NetworkScanQueryParams {
        NetworkScanQueryParams {
            ping_interval: None,
            ping_timeout: None,
            broadcast_timeout: None,
            port_scan_timeout: None,
            netbios_timeout: None,
            netbios_interval: None,
            mdns_query_timeout: None,
            max_wait: None,
            ranges: Vec::new(),
            targets: Vec::new(),
            interface_ids: Vec::new(),
            probes: vec!["ping".to_owned()],
            enable_ping_start: false,
            enable_broadcast: true,
            enable_subnet_scan: true,
            enable_zeroconf: true,
            enable_netbios: true,
            enable_resolve_dns: true,
            include_host_results: true,
            report_ping_status: false,
            report_ping_start: false,
            report_ping_success: false,
            report_ping_failure: false,
            enable_tcp_probes: true,
            range_interface_policy: None,
            allow_cross_interface_range: false,
            response_format: None,
            max_concurrency: None,
            max_ping_concurrency: None,
            max_tcp_probe_concurrency: None,
            enable_failure: false,
            report_tcp_failure: false,
            interface_bind_strict: false,
        }
    }
}
