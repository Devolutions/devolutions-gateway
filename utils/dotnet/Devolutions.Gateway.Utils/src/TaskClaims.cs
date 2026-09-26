using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class TaskClaims : IGatewayClaims
{
    [JsonPropertyName("jet_tk")]
    public string TaskKind { get; set; }

    [JsonPropertyName("jet_aid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Guid? SessionId { get; set; }

    [JsonPropertyName("jet_task_reuse")]
    public bool Reusable { get; set; }

    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }

    private TaskClaims(Guid scopeGatewayId, string taskKind, bool reusable)
    {
        this.ScopeGatewayId = scopeGatewayId;
        this.TaskKind = taskKind;
        this.Reusable = reusable;
    }

    /// <summary>
    /// Build the claims of a task that describes what the user did in one session and stores the result as a new log of that session.
    /// </summary>
    /// <param name="scopeGatewayId">Target Gateway identifier.</param>
    /// <param name="sessionId">Session to describe.</param>
    /// <param name="reusable">When true, the token can be used until it expires; otherwise it is single use.</param>
    public static TaskClaims ForAiLog(Guid scopeGatewayId, Guid sessionId, bool reusable = false)
    {
        return new TaskClaims(scopeGatewayId, "ai-log", reusable)
        {
            SessionId = sessionId,
        };
    }

    public string GetContentType()
    {
        return "TASK";
    }

    public long? GetDefaultLifetime()
    {
        return 600;
    }
}
