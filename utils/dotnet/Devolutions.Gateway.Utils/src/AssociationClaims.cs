using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class AssociationClaims : IGatewayClaims
{
    [JsonPropertyName("dst_hst")]
    public TargetAddr DestinationHost { get; set; }
    [JsonPropertyName("dst_alt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<TargetAddr>? AlternateDestinations { get; set; }
    [JsonPropertyName("jet_ap")]
    public ApplicationProtocol ApplicationProtocol { get; set; }
    [JsonPropertyName("jet_cm")]
    public string ConnectionMode { get; set; }
    [JsonPropertyName("jet_aid")]
    public Guid SessionId { get; set; }
    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }
    [JsonPropertyName("jet_ttl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SessionTtl? TimeToLive { get; set; }
    [JsonPropertyName("jet_rec")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public RecordingPolicy? RecordingPolicy { get; set; }
    [JsonPropertyName("jet_reuse")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ReusePolicy? ReusePolicy { get; set; }

    public AssociationClaims(
        Guid scopeGatewayId,
        TargetAddr destinationHost,
        ApplicationProtocol applicationProtocol,
        Guid sessionId,
        SessionTtl? TimeToLive = null,
        RecordingPolicy? RecordingPolicy = null,
        ReusePolicy? ReusePolicy = null)
    {
        this.DestinationHost = destinationHost;
        this.ApplicationProtocol = applicationProtocol;
        this.ConnectionMode = "fwd";
        this.SessionId = sessionId;
        this.ScopeGatewayId = scopeGatewayId;
        this.TimeToLive = TimeToLive;
        this.RecordingPolicy = RecordingPolicy;
        this.ReusePolicy = ReusePolicy;
    }

    public string GetContentType()
    {
        return "ASSOCIATION";
    }
}