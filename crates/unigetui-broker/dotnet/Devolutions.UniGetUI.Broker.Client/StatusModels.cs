using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>Request to query the status of a previously submitted package operation.</summary>
public sealed class StatusRequest
{
    [JsonPropertyName("RequestId")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("Broker")]
    public BrokerContext Broker { get; set; } = new();
}

/// <summary>Response to a status query.</summary>
public sealed class StatusResponse
{
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

    /// <summary>
    /// Captured combined stdout+stderr of the operation (UTF-8, tail-truncated to ~10 KiB).
    /// Only present when the request opted in via <see cref="PackageRequest.CaptureOutput"/>.
    /// </summary>
    [JsonPropertyName("Stdout")]
    public string? Stdout { get; set; }
}
