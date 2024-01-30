using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class NetScanClaims : IGatewayClaims
{
    [JsonPropertyName("jet_gw_id")]
    public Guid GatewayId { get; set; }

    public NetScanClaims(
        Guid gatewayId
    )
    {
        this.GatewayId = gatewayId;
    }

    public string GetContentType()
    {
        return "NETSCAN";
    }
}