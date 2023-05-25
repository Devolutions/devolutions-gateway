using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class JrlClaims : IGatewayClaims
{
    [JsonPropertyName("jrl")]
    public RevocationList RevocationList { get; set; }

    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }

    public JrlClaims(Guid scopeGatewayId, RevocationList revocationList)
    {
        this.RevocationList = revocationList;
        this.ScopeGatewayId = scopeGatewayId;
    }

    public string GetContentType()
    {
        return "JRL";
    }

    public long? GetDefaultLifetime()
    {
        return null;
    }
}
