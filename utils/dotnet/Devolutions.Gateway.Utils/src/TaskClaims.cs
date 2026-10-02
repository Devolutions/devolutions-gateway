using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class TaskClaims : IGatewayClaims
{
    [JsonPropertyName("jet_tk")]
    public TaskKind TaskKind { get; set; }

    [JsonPropertyName("jet_aid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Guid? SessionId { get; set; }

    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }

    private TaskClaims(Guid scopeGatewayId, TaskKind taskKind)
    {
        this.ScopeGatewayId = scopeGatewayId;
        this.TaskKind = taskKind;
    }

    /// <summary>
    /// Build the claims of a task that describes what the user did in one session and stores the result as a new log of that session.
    /// </summary>
    /// <param name="scopeGatewayId">Target Gateway identifier.</param>
    /// <param name="sessionId">Session to describe.</param>
    public static TaskClaims ForAiLog(Guid scopeGatewayId, Guid sessionId)
    {
        return new TaskClaims(scopeGatewayId, TaskKind.AiLog)
        {
            SessionId = sessionId,
        };
    }

    public string GetContentType()
    {
        return "TASK";
    }
}
