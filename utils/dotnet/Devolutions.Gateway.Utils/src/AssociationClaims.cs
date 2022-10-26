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

    public AssociationClaims(
        Guid scopeGatewayId,
        TargetAddr destinationHost,
        ApplicationProtocol applicationProtocol,
        Guid sessionId)
    {
        this.DestinationHost = destinationHost;
        this.ApplicationProtocol = applicationProtocol;
        this.ConnectionMode = "fwd";
        this.SessionId = sessionId;
        this.ScopeGatewayId = scopeGatewayId;
    }

    public string GetContentType()
    {
        return "ASSOCIATION";
    }
}