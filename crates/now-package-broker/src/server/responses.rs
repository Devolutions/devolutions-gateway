//! NOW API response mapping helpers.

use chrono::{DateTime, Utc};
use now_policy::PolicyDocument;
use now_policy_api::{
    API_VERSION_STR, ApiVersion, Architecture, ErrorCode, ErrorResponse, ErrorResponseKind, ManagerCapability,
    ManagerName, Operation, OperationDiagnostics, PackageRequest, RequestSummary, ResourceId, ResponsePolicyInfo,
    RuleId, Scope, SemanticVersion, ServerContext, Transport,
};

use crate::operation_tracker::OperationTracker;

pub(super) fn api_version() -> ApiVersion {
    API_VERSION_STR.into()
}

pub(super) fn server_context() -> ServerContext {
    ServerContext {
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        transport: Transport::HttpNamedPipe,
    }
}

/// Capability descriptions for every manager the broker can drive.
///
/// This is the full supported set; the server filters it down to the managers actually
/// available for the requesting user (see [`crate::server::BrokerState`]).
pub(super) fn supported_manager_capabilities() -> Vec<ManagerCapability> {
    vec![
        ManagerCapability {
            manager: ManagerName::Winget,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User, Scope::Machine],
            architectures: vec![
                Architecture::X86,
                Architecture::X64,
                Architecture::Arm64,
                Architecture::Neutral,
            ],
            supports_custom_parameters: true,
            supports_custom_install_location: true,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Chocolatey,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::Machine],
            architectures: vec![Architecture::X86, Architecture::X64],
            supports_custom_parameters: false,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Bun,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: false,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Cargo,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: false,
            supports_custom_install_location: true,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Dotnet,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![
                Architecture::X86,
                Architecture::X64,
                Architecture::Arm64,
                Architecture::Neutral,
            ],
            supports_custom_parameters: false,
            supports_custom_install_location: true,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Pip,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: false,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Npm,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: false,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::PowerShell,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User, Scope::Machine],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: true,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::PowerShell7,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User, Scope::Machine],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: true,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Scoop,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![Architecture::X86, Architecture::X64, Architecture::Arm64],
            supports_custom_parameters: true,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
        ManagerCapability {
            manager: ManagerName::Vcpkg,
            operations: vec![Operation::Install, Operation::Update, Operation::Uninstall],
            scopes: vec![Scope::User],
            architectures: vec![Architecture::Neutral],
            supports_custom_parameters: false,
            supports_custom_install_location: false,
            supports_capture_output: true,
            supports_details: false,
            max_operation_timeout_seconds: Some(OperationTracker::operation_timeout().as_secs()),
        },
    ]
}

/// Keep only the capabilities of managers reported available by the probe.
pub(super) fn filter_manager_capabilities(
    all: Vec<ManagerCapability>,
    available: &[ManagerName],
) -> Vec<ManagerCapability> {
    all.into_iter()
        .filter(|capability| available.contains(&capability.manager))
        .collect()
}

pub(super) fn request_summary(request: &PackageRequest) -> RequestSummary {
    RequestSummary {
        manager: Some(request.manager),
        source: Some(request.source.name.clone()),
        package_id: Some(request.package.id.clone()),
        operation: Some(request.operation),
    }
}

pub(super) fn policy_info(policy: &PolicyDocument) -> ResponsePolicyInfo {
    ResponsePolicyInfo {
        id: ResourceId(policy.metadata.id.0.clone()),
        revision: policy.metadata.revision,
        policy_version: SemanticVersion(policy.policy_version.0.clone()),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "the shared API contract requires ErrorResponse values"
)]
pub(super) fn diagnostics(
    command: &[String],
    include_command_preview: bool,
) -> Result<Option<OperationDiagnostics>, ErrorResponse> {
    if !include_command_preview {
        return Ok(None);
    }

    let mut command_preview = Vec::with_capacity(command.len());
    for arg in command {
        let parsed = now_policy_api::CommandString::parse(arg).map_err(|error| {
            error_response(
                ErrorCode::InternalError,
                format!("failed to build command preview: {error}"),
            )
        })?;
        command_preview.push(parsed);
    }

    Ok(Some(OperationDiagnostics { command_preview }))
}

#[expect(
    clippy::result_large_err,
    reason = "the shared API contract requires ErrorResponse values"
)]
pub(super) fn parse_rule_id(rule_id: &str) -> Result<RuleId, ErrorResponse> {
    RuleId::parse(rule_id).map_err(|error| {
        error_response(
            ErrorCode::InternalError,
            format!("invalid policy rule id in evaluation result: {error}"),
        )
    })
}

#[expect(
    clippy::result_large_err,
    reason = "the shared API contract requires ErrorResponse values"
)]
pub(super) fn new_operation_id() -> Result<ResourceId, ErrorResponse> {
    let raw = format!("op-{}", uuid::Uuid::new_v4());
    ResourceId::parse(&raw).map_err(|error| {
        error_response(
            ErrorCode::InternalError,
            format!("failed to generate operation id: {error}"),
        )
    })
}

pub(super) fn policy_validity_failure(policy: &PolicyDocument, now: DateTime<Utc>) -> Option<String> {
    if let Some(valid_from) = policy.metadata.valid_from
        && now < valid_from
    {
        return Some(format!("policy is not active until {valid_from} (current time {now})"));
    }
    if let Some(valid_until) = policy.metadata.valid_until
        && now > valid_until
    {
        return Some(format!("policy expired at {valid_until} (current time {now})"));
    }
    None
}

pub(super) fn error_response(code: ErrorCode, message: impl Into<String>) -> ErrorResponse {
    ErrorResponse {
        response_kind: ErrorResponseKind,
        response_version: api_version(),
        server: server_context(),
        code,
        message: message.into(),
        details: Vec::new(),
        validation: None,
        management: None,
    }
}
