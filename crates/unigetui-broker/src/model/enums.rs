//! Shared enumerations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Package operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "operation")]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Install,
    Update,
    Uninstall,
}

/// Package installation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "scope")]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Machine,
}

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "architecture")]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
    Arm64,
    Neutral,
}

/// Supported package manager names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "managerName")]
pub enum ManagerName {
    Winget,
    PowerShell,
}

/// Policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "decision")]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

/// Requested elevation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "elevation")]
#[serde(rename_all = "lowercase")]
pub enum Elevation {
    Standard,
    Elevated,
}

/// Broker transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "transport")]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    HttpNamedPipe,
    HttpLoopbackSimulator,
}

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "executionMode")]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    SimulatedElevated,
    Elevated,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Display implementations
// ═══════════════════════════════════════════════════════════════════════════════

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Install => f.write_str("install"),
            Self::Update => f.write_str("update"),
            Self::Uninstall => f.write_str("uninstall"),
        }
    }
}

impl std::fmt::Display for ManagerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Winget => f.write_str("Winget"),
            Self::PowerShell => f.write_str("PowerShell"),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => f.write_str("user"),
            Self::Machine => f.write_str("machine"),
        }
    }
}

impl std::fmt::Display for Elevation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => f.write_str("standard"),
            Self::Elevated => f.write_str("elevated"),
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => f.write_str("x86"),
            Self::X64 => f.write_str("x64"),
            Self::Arm64 => f.write_str("arm64"),
            Self::Neutral => f.write_str("neutral"),
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimulatedElevated => f.write_str("simulated-elevated"),
            Self::Elevated => f.write_str("elevated"),
        }
    }
}
