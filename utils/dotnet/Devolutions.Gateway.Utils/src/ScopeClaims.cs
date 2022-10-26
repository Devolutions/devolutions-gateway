using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class ScopeClaims : IGatewayClaims
{
    [JsonPropertyName("scope")]
    public AccessScope Scope { get; set; }
    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }

    public ScopeClaims(
        Guid scopeGatewayId,
        AccessScope scope)
    {
        this.Scope = scope;
        this.ScopeGatewayId = scopeGatewayId;
    }

    public string GetContentType()
    {
        return "SCOPE";
    }
}