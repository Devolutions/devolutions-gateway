using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>Canonical request sent by an unelevated UniGetUI process to the elevated broker.</summary>
public sealed class PackageRequest
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = SchemaUris.Request;

    [JsonPropertyName("RequestVersion")]
    public string RequestVersion { get; set; } = "1.0.0";

    [JsonPropertyName("RequestType")]
    public string RequestType { get; set; } = "PackageOperation";

    [JsonPropertyName("RequestId")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("CreatedAt")]
    public DateTimeOffset CreatedAt { get; set; }

    [JsonPropertyName("Operation")]
    public Operation Operation { get; set; }

    [JsonPropertyName("Manager")]
    public RequestManager Manager { get; set; } = new();

    [JsonPropertyName("Source")]
    public RequestSource Source { get; set; } = new();

    [JsonPropertyName("Package")]
    public RequestPackage Package { get; set; } = new();

    [JsonPropertyName("Options")]
    public RequestOptions Options { get; set; } = new();

    [JsonPropertyName("Broker")]
    public BrokerContext Broker { get; set; } = new();
}

public sealed class RequestManager
{
    [JsonPropertyName("Name")]
    public ManagerName Name { get; set; }

    [JsonPropertyName("DisplayName")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("ExecutableFriendlyName")]
    public string ExecutableFriendlyName { get; set; } = "";
}

public sealed class RequestSource
{
    [JsonPropertyName("Name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("Url")]
    public string? Url { get; set; }

    [JsonPropertyName("IsVirtualManager")]
    public bool? IsVirtualManager { get; set; }
}

public sealed class RequestPackage
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("Name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("Version")]
    public string? Version { get; set; }

    [JsonPropertyName("Architecture")]
    public Architecture? Architecture { get; set; }

    [JsonPropertyName("Channel")]
    public string? Channel { get; set; }
}

public sealed class RequestOptions
{
    [JsonPropertyName("Scope")]
    public Scope? Scope { get; set; }

    [JsonPropertyName("Interactive")]
    public bool Interactive { get; set; }

    [JsonPropertyName("SkipHashCheck")]
    public bool SkipHashCheck { get; set; }

    [JsonPropertyName("PreRelease")]
    public bool PreRelease { get; set; }

    [JsonPropertyName("CustomInstallLocation")]
    public string? CustomInstallLocation { get; set; }

    [JsonPropertyName("CustomParameters")]
    public List<string> CustomParameters { get; set; } = [];

    [JsonPropertyName("PreOperationCommand")]
    public string? PreOperationCommand { get; set; }

    [JsonPropertyName("PostOperationCommand")]
    public string? PostOperationCommand { get; set; }

    [JsonPropertyName("KillBeforeOperation")]
    public List<string> KillBeforeOperation { get; set; } = [];

    [JsonPropertyName("UninstallPrevious")]
    public bool UninstallPrevious { get; set; }

    [JsonPropertyName("NoUpgrade")]
    public bool NoUpgrade { get; set; }
}

public sealed class BrokerContext
{
    [JsonPropertyName("RequestedElevation")]
    public Elevation RequestedElevation { get; set; }

    [JsonPropertyName("EffectiveUser")]
    public string EffectiveUser { get; set; } = "";

    [JsonPropertyName("ClientVersion")]
    public string? ClientVersion { get; set; }

    [JsonPropertyName("ClientProcessPath")]
    public string? ClientProcessPath { get; set; }
}
