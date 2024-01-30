using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class NetworkScanClaims : IGatewayClaims
{
    [JsonPropertyName("jet_gw_id")]
    public Guid GatewayId { get; set; }

    public NetworkScanClaims(
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