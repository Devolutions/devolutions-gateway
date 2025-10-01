using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class RecordingClaims : IGatewayClaims
{
    [JsonPropertyName("jet_aid")]
    public Guid SessionId { get; set; }
    [JsonPropertyName("jet_rop")]
    public RecordingOperation RecordingOperation { get; set; }
    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }
    [JsonPropertyName("jet_reuse")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ReusePolicy? ReusePolicy { get; set; }

    public RecordingClaims(
        Guid scopeGatewayId,
        Guid sessionId,
        RecordingOperation recordingOperation,
        ReusePolicy? ReusePolicy = null)
    {
        this.ScopeGatewayId = scopeGatewayId;
        this.SessionId = sessionId;
        this.RecordingOperation = recordingOperation;
        this.ReusePolicy = ReusePolicy;
    }

    public string GetContentType()
    {
        return "JREC";
    }

    public long? GetDefaultLifetime()
    {
        return 14400;
    }
}