using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class KdcClaims : IGatewayClaims
{
    [JsonPropertyName("krb_kdc")]
    public TargetAddr KrbKdc { get; set; }
    [JsonPropertyName("krb_realm")]
    public string KrbRealm { get; set; }
    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }

    public KdcClaims(Guid scopeGatewayId, TargetAddr krbKdc, string krbRealm)
    {
        this.KrbKdc = krbKdc;
        this.KrbRealm = krbRealm.ToLower();
        this.ScopeGatewayId = scopeGatewayId;
    }

    public string GetContentType()
    {
        return "KDC";
    }
}