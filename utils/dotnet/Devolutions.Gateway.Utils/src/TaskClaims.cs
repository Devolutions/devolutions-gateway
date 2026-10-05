using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class TaskClaims : IGatewayClaims
{
    [JsonPropertyName("jet_task")]
    public TaskSpec Task { get; }

    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; }

    private TaskClaims(Guid scopeGatewayId, TaskPayload payload)
    {
        this.ScopeGatewayId = scopeGatewayId;
        this.Task = new TaskSpec(payload);
    }

    /// <summary>
    /// Build the claims of a task that describes what the user did in one session and stores the result as a new log of that session.
    /// </summary>
    /// <param name="scopeGatewayId">Target Gateway identifier.</param>
    /// <param name="payload">What the task works on and how it calls the AI provider.</param>
    public static TaskClaims ForRecordingAiAnalysis(Guid scopeGatewayId, RecordingAiAnalysisPayload payload)
    {
        return new TaskClaims(scopeGatewayId, payload);
    }

    public string GetContentType()
    {
        return "TASK";
    }
}
