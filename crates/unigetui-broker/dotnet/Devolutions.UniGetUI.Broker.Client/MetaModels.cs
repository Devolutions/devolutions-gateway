using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>Response body for <c>GET /v1/health</c>.</summary>
public sealed class HealthResponse
{
    [JsonPropertyName("Status")]
    public HealthStatus Status { get; set; }

    [JsonPropertyName("ProtocolVersion")]
    public string ProtocolVersion { get; set; } = "1.0";

    [JsonPropertyName("ElevatedSimulation")]
    public bool ElevatedSimulation { get; set; }

    [JsonPropertyName("PolicyId")]
    public string PolicyId { get; set; } = "";

    [JsonPropertyName("Endpoints")]
    public List<string> Endpoints { get; set; } = [];
}

/// <summary>Response body for <c>GET /v1/capabilities</c>.</summary>
public sealed class CapabilitiesResponse
{
    [JsonPropertyName("ProtocolVersion")]
    public string ProtocolVersion { get; set; } = "1.0";

    [JsonPropertyName("Transports")]
    public List<Transport> Transports { get; set; } = [];

    [JsonPropertyName("RequestMediaTypes")]
    public List<string> RequestMediaTypes { get; set; } = [];

    [JsonPropertyName("ResponseMediaTypes")]
    public List<string> ResponseMediaTypes { get; set; } = [];

    [JsonPropertyName("SupportedManagers")]
    public List<ManagerName> SupportedManagers { get; set; } = [];

    [JsonPropertyName("SupportedOperations")]
    public List<Operation> SupportedOperations { get; set; } = [];

    [JsonPropertyName("MaxRequestBodyBytes")]
    public long MaxRequestBodyBytes { get; set; }

    [JsonPropertyName("PipeName")]
    public string PipeName { get; set; } = "";
}

/// <summary>Generic error body returned for failures not described by a <see cref="BrokerResponse"/>.</summary>
public sealed class ErrorResponse
{
    [JsonPropertyName("Error")]
    public string Error { get; set; } = "";

    [JsonPropertyName("Reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("AuditId")]
    public string? AuditId { get; set; }
}
