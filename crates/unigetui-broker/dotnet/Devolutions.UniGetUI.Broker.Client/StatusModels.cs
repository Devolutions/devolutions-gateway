using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>Request to query the status of a previously submitted package operation.</summary>
public sealed class StatusRequest
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = SchemaUris.StatusRequest;

    [JsonPropertyName("RequestVersion")]
    public string RequestVersion { get; set; } = "1.0.0";

    [JsonPropertyName("RequestType")]
    public string RequestType { get; set; } = "PackageOperationStatus";

    [JsonPropertyName("RequestId")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("Broker")]
    public BrokerContext Broker { get; set; } = new();
}

/// <summary>Response to a status query.</summary>
public sealed class StatusResponse
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = SchemaUris.StatusResponse;

    [JsonPropertyName("ResponseVersion")]
    public string ResponseVersion { get; set; } = "1.0.0";

    [JsonPropertyName("ResponseType")]
    public string ResponseType { get; set; } = "PackageOperationStatusResponse";

    [JsonPropertyName("Broker")]
    public BrokerInfo Broker { get; set; } = new();

    [JsonPropertyName("RequestId")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("Status")]
    public OperationStatus Status { get; set; }

    [JsonPropertyName("StartedAt")]
    public DateTimeOffset? StartedAt { get; set; }

    [JsonPropertyName("CompletedAt")]
    public DateTimeOffset? CompletedAt { get; set; }

    [JsonPropertyName("ExitCode")]
    public int? ExitCode { get; set; }

    [JsonPropertyName("Note")]
    public string? Note { get; set; }
}
