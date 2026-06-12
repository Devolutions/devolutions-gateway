using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>Canonical response returned by the broker after evaluating a request.</summary>
public sealed class BrokerResponse
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = SchemaUris.Response;

    [JsonPropertyName("ResponseVersion")]
    public string ResponseVersion { get; set; } = "1.0.0";

    [JsonPropertyName("ResponseType")]
    public string ResponseType { get; set; } = "PackageBrokerResponse";

    [JsonPropertyName("Broker")]
    public BrokerInfo Broker { get; set; } = new();

    [JsonPropertyName("AuditId")]
    public string AuditId { get; set; } = "";

    [JsonPropertyName("RequestId")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("ReceivedAt")]
    public DateTimeOffset ReceivedAt { get; set; }

    [JsonPropertyName("CompletedAt")]
    public DateTimeOffset CompletedAt { get; set; }

    [JsonPropertyName("Manager")]
    public string? Manager { get; set; }

    [JsonPropertyName("Source")]
    public string? Source { get; set; }

    [JsonPropertyName("PackageId")]
    public string? PackageId { get; set; }

    [JsonPropertyName("Operation")]
    public Operation? Operation { get; set; }

    [JsonPropertyName("Decision")]
    public Decision Decision { get; set; }

    [JsonPropertyName("RuleId")]
    public string RuleId { get; set; } = "";

    [JsonPropertyName("Reason")]
    public string Reason { get; set; } = "";

    [JsonPropertyName("WouldExecute")]
    public bool WouldExecute { get; set; }

    [JsonPropertyName("Policy")]
    public ResponsePolicyInfo Policy { get; set; } = new();

    [JsonPropertyName("Execution")]
    public ExecutionInfo Execution { get; set; } = new();
}

public sealed class BrokerInfo
{
    [JsonPropertyName("Name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("ProtocolVersion")]
    public string ProtocolVersion { get; set; } = "1.0";

    [JsonPropertyName("Transport")]
    public Transport Transport { get; set; }

    [JsonPropertyName("PipeName")]
    public string? PipeName { get; set; }

    [JsonPropertyName("ElevatedSimulation")]
    public bool ElevatedSimulation { get; set; }
}

public sealed class ResponsePolicyInfo
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("Revision")]
    public int Revision { get; set; }

    [JsonPropertyName("PolicyVersion")]
    public string PolicyVersion { get; set; } = "1.0.0";
}

public sealed class ExecutionInfo
{
    [JsonPropertyName("Mode")]
    public ExecutionMode Mode { get; set; }

    [JsonPropertyName("Command")]
    public List<string> Command { get; set; } = [];

    [JsonPropertyName("Note")]
    public string Note { get; set; } = "";
}
