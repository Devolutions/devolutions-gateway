//! Shared enumerations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Package operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Operation")]
pub enum Operation {
    Install,
    Update,
    Uninstall,
}

/// Package installation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Scope")]
pub enum Scope {
    User,
    Machine,
}

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Architecture")]
pub enum Architecture {
    X86,
    X64,
    Arm64,
    Neutral,
}

/// Supported package manager names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "ManagerName")]
pub enum ManagerName {
    Winget,
    PowerShell,
    PowerShell7,
}

/// Policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Decision")]
pub enum Decision {
    Allow,
    Deny,
}

/// Requested elevation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Elevation")]
pub enum Elevation {
    Standard,
    Elevated,
}

/// Broker transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Transport")]
pub enum Transport {
    HttpNamedPipe,
    HttpLoopbackSimulator,
}

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "ExecutionMode")]
pub enum ExecutionMode {
    SimulatedElevated,
    Elevated,
}

/// Status of an asynchronous package operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "OperationStatus")]
pub enum OperationStatus {
    /// Process is being prepared/started.
    Starting,
    /// Process is running.
    Running,
    /// Process exited successfully (exit code 0).
    Completed,
    /// Process failed (non-zero exit, timeout, or launch failure).
    Failed,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Display implementations
// ═══════════════════════════════════════════════════════════════════════════════

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Deny => f.write_str("Deny"),
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Install => f.write_str("Install"),
            Self::Update => f.write_str("Update"),
            Self::Uninstall => f.write_str("Uninstall"),
        }
    }
}

impl std::fmt::Display for ManagerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Winget => f.write_str("Winget"),
            Self::PowerShell => f.write_str("PowerShell"),
            Self::PowerShell7 => f.write_str("PowerShell7"),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => f.write_str("User"),
            Self::Machine => f.write_str("Machine"),
        }
    }
}

impl std::fmt::Display for Elevation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => f.write_str("Standard"),
            Self::Elevated => f.write_str("Elevated"),
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => f.write_str("X86"),
            Self::X64 => f.write_str("X64"),
            Self::Arm64 => f.write_str("Arm64"),
            Self::Neutral => f.write_str("Neutral"),
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimulatedElevated => f.write_str("SimulatedElevated"),
            Self::Elevated => f.write_str("Elevated"),
        }
    }
}
