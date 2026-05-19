using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class KdcClaims : IGatewayClaims
{
    [JsonPropertyName("krb_kdc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TargetAddr? KrbKdc { get; set; }

    [JsonPropertyName("krb_realm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KrbRealm { get; set; }

    [JsonPropertyName("jet_cred_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Guid? JetCredId { get; set; }

    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }

    public KdcClaims(Guid scopeGatewayId, TargetAddr krbKdc, string krbRealm)
    {
        this.KrbKdc = krbKdc;
        this.KrbRealm = krbRealm.ToLower();
        this.ScopeGatewayId = scopeGatewayId;
    }

    private KdcClaims(Guid scopeGatewayId, Guid jetCredId)
    {
        this.JetCredId = jetCredId;
        this.ScopeGatewayId = scopeGatewayId;
    }

    /// <summary>
    /// Build a KDC claims set whose KDC traffic is served locally using credentials provisioned
    /// at session establishment, rather than forwarded to an upstream KDC.
    /// </summary>
    /// <param name="scopeGatewayId">Target Gateway identifier.</param>
    /// <param name="jetCredId">JTI of the access token whose credentials must be used.</param>
    public static KdcClaims ForCredentialInjection(Guid scopeGatewayId, Guid jetCredId)
    {
        return new KdcClaims(scopeGatewayId, jetCredId);
    }

    public string GetContentType()
    {
        return "KDC";
    }
}