using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>A policy document governing which package operations are allowed or denied.</summary>
public sealed class PolicyDocument
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = SchemaUris.Policy;

    [JsonPropertyName("PolicyVersion")]
    public string PolicyVersion { get; set; } = "1.0.0";

    [JsonPropertyName("PolicyType")]
    public string PolicyType { get; set; } = "PackageBrokerPolicy";

    [JsonPropertyName("Metadata")]
    public PolicyMetadata Metadata { get; set; } = new();

    [JsonPropertyName("Enforcement")]
    public PolicyEnforcement Enforcement { get; set; } = new();

    [JsonPropertyName("Rules")]
    public List<PolicyRule> Rules { get; set; } = [];
}

public sealed class PolicyMetadata
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("Publisher")]
    public string Publisher { get; set; } = "";

    [JsonPropertyName("Revision")]
    public int Revision { get; set; }

    [JsonPropertyName("PublishedAt")]
    public DateTimeOffset PublishedAt { get; set; }

    [JsonPropertyName("ValidFrom")]
    public DateTimeOffset? ValidFrom { get; set; }

    [JsonPropertyName("ValidUntil")]
    public DateTimeOffset? ValidUntil { get; set; }

    [JsonPropertyName("Description")]
    public string? Description { get; set; }

    [JsonPropertyName("SupportUrl")]
    public string? SupportUrl { get; set; }
}

public sealed class PolicyEnforcement
{
    [JsonPropertyName("DefaultDecision")]
    public Decision DefaultDecision { get; set; }

    [JsonPropertyName("RulePrecedence")]
    public RulePrecedence RulePrecedence { get; set; }

    [JsonPropertyName("AuditMode")]
    public bool? AuditMode { get; set; }
}

public sealed class PolicyRule
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("Enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("Priority")]
    public int Priority { get; set; }

    [JsonPropertyName("Decision")]
    public Decision Decision { get; set; }

    [JsonPropertyName("Reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("Match")]
    public PolicyMatch Match { get; set; } = new();

    [JsonPropertyName("Constraints")]
    public PolicyConstraints? Constraints { get; set; }
}

public sealed class PolicyMatch
{
    [JsonPropertyName("Operations")]
    public List<Operation> Operations { get; set; } = [];

    [JsonPropertyName("Managers")]
    public List<ManagerName> Managers { get; set; } = [];

    [JsonPropertyName("Sources")]
    public List<string> Sources { get; set; } = [];

    [JsonPropertyName("PackageIdentifiers")]
    public List<string> PackageIdentifiers { get; set; } = [];

    [JsonPropertyName("PackageNames")]
    public List<string> PackageNames { get; set; } = [];

    [JsonPropertyName("Versions")]
    public List<string> Versions { get; set; } = [];

    [JsonPropertyName("VersionRange")]
    public VersionRange? VersionRange { get; set; }

    [JsonPropertyName("Scopes")]
    public List<Scope> Scopes { get; set; } = [];

    [JsonPropertyName("Architectures")]
    public List<Architecture> Architectures { get; set; } = [];

    [JsonPropertyName("Elevation")]
    public List<Elevation> Elevation { get; set; } = [];

    [JsonPropertyName("Interactive")]
    public List<bool> Interactive { get; set; } = [];

    [JsonPropertyName("SkipHashCheck")]
    public List<bool> SkipHashCheck { get; set; } = [];

    [JsonPropertyName("PreRelease")]
    public List<bool> PreRelease { get; set; } = [];

    [JsonPropertyName("HasCustomParameters")]
    public List<bool> HasCustomParameters { get; set; } = [];

    [JsonPropertyName("HasCustomInstallLocation")]
    public List<bool> HasCustomInstallLocation { get; set; } = [];

    [JsonPropertyName("HasPrePostCommands")]
    public List<bool> HasPrePostCommands { get; set; } = [];

    [JsonPropertyName("HasKillBeforeOperation")]
    public List<bool> HasKillBeforeOperation { get; set; } = [];

    [JsonPropertyName("HasUninstallPrevious")]
    public List<bool> HasUninstallPrevious { get; set; } = [];
}

public sealed class VersionRange
{
    [JsonPropertyName("MinVersion")]
    public string? MinVersion { get; set; }

    [JsonPropertyName("MaxVersion")]
    public string? MaxVersion { get; set; }

    [JsonPropertyName("IncludePrerelease")]
    public bool IncludePrerelease { get; set; }
}

public sealed class PolicyConstraints
{
    [JsonPropertyName("AllowInteractive")]
    public bool AllowInteractive { get; set; } = true;

    [JsonPropertyName("AllowSkipHashCheck")]
    public bool AllowSkipHashCheck { get; set; } = true;

    [JsonPropertyName("AllowPreRelease")]
    public bool AllowPreRelease { get; set; } = true;

    [JsonPropertyName("AllowCustomInstallLocation")]
    public bool AllowCustomInstallLocation { get; set; } = true;

    [JsonPropertyName("AllowedInstallLocationPatterns")]
    public List<string> AllowedInstallLocationPatterns { get; set; } = [];

    [JsonPropertyName("AllowCustomParameters")]
    public bool AllowCustomParameters { get; set; } = true;

    [JsonPropertyName("AllowedCustomParameters")]
    public List<string> AllowedCustomParameters { get; set; } = [];

    [JsonPropertyName("AllowedCustomParameterPatterns")]
    public List<string> AllowedCustomParameterPatterns { get; set; } = [];

    [JsonPropertyName("DeniedCustomParameters")]
    public List<string> DeniedCustomParameters { get; set; } = [];

    [JsonPropertyName("AllowPrePostCommands")]
    public bool AllowPrePostCommands { get; set; } = true;

    [JsonPropertyName("AllowKillBeforeOperation")]
    public bool AllowKillBeforeOperation { get; set; } = true;

    [JsonPropertyName("AllowUninstallPrevious")]
    public bool AllowUninstallPrevious { get; set; } = true;

    [JsonPropertyName("AllowUpgrade")]
    public bool AllowUpgrade { get; set; } = true;
}
