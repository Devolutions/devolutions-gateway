using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

// Enum members are spelled exactly as they appear on the wire (PascalCase), so the
// default JsonStringEnumConverter round-trips them without a naming policy.

/// <summary>Package operation type.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Operation>))]
public enum Operation
{
    Install,
    Update,
    Uninstall,
}

/// <summary>Supported package manager names.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ManagerName>))]
public enum ManagerName
{
    Winget,
    PowerShell,
    PowerShell7,
}

/// <summary>Installation scope.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Scope>))]
public enum Scope
{
    User,
    Machine,
}

/// <summary>Target architecture.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Architecture>))]
public enum Architecture
{
    X86,
    X64,
    Arm64,
    Neutral,
}

/// <summary>Requested elevation level.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Elevation>))]
public enum Elevation
{
    Standard,
    Elevated,
}

/// <summary>Policy decision.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Decision>))]
public enum Decision
{
    Allow,
    Deny,
}

/// <summary>Broker transport type.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Transport>))]
public enum Transport
{
    HttpNamedPipe,
    HttpLoopbackSimulator,
}

/// <summary>Execution mode.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ExecutionMode>))]
public enum ExecutionMode
{
    SimulatedElevated,
    Elevated,
}

/// <summary>Status of an asynchronous package operation.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<OperationStatus>))]
public enum OperationStatus
{
    Starting,
    Running,
    Completed,
    Failed,
}

/// <summary>Rule precedence strategy.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<RulePrecedence>))]
public enum RulePrecedence
{
    PriorityThenDeny,
}
