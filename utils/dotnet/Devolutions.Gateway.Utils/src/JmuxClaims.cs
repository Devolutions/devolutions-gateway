using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class JmuxClaims : IGatewayClaims
{
    [JsonPropertyName("dst_hst")]
    public TargetAddr Destination { get; set; }
    [JsonPropertyName("dst_addl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<TargetAddr>? AdditionalDestinations { get; set; }
    [JsonPropertyName("jet_ap")]
    public ApplicationProtocol ApplicationProtocol { get; set; }
    [JsonPropertyName("jet_aid")]
    public Guid SessionId { get; set; }
    [JsonPropertyName("jet_gw_id")]
    public Guid ScopeGatewayId { get; set; }
    [JsonPropertyName("jet_ttl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SessionTtl? TimeToLive { get; set; }

    public JmuxClaims(
        Guid scopeGatewayId,
        TargetAddr destinationHost,
        ApplicationProtocol applicationProtocol,
        Guid sessionId,
        SessionTtl? TimeToLive = null)
    {
        this.Destination = destinationHost;
        this.ApplicationProtocol = applicationProtocol;
        this.SessionId = sessionId;
        this.ScopeGatewayId = scopeGatewayId;
        this.TimeToLive = TimeToLive;
    }

    public void HttpAllowAnyAdditional()
    {
        if (this.AdditionalDestinations is null)
        {
            this.AdditionalDestinations = new List<TargetAddr>();
        }

        this.AdditionalDestinations.Add(new TargetAddr("http", "*", 80));
        this.AdditionalDestinations.Add(new TargetAddr("https", "*", 443));
    }

    /// <summary>Add common redirections as additional destinations.</summary>
    public void HttpExpandAdditionals()
    {
        if (this.AdditionalDestinations is null)
        {
            this.AdditionalDestinations = new List<TargetAddr>();
        }

        bool isPlainHttp = this.ApplicationProtocol.Equals(ApplicationProtocol.Http) || this.Destination.Port == 80 || this.Destination.Scheme == "http";

        if (isPlainHttp)
        {
            // e.g.: http://www.google.com:80 => https://www.google.com:443
            this.AdditionalDestinations.Add($"https://{this.Destination.Host}:443");
        }

        if (!this.Destination.Host.Contains("www"))
        {
            // e.g.: http://google.com:80 => http://www.google.com:80
            this.AdditionalDestinations.Add($"{this.Destination.Scheme}://www.{this.Destination.Host}:{this.Destination.Port}");

            if (isPlainHttp)
            {
                // e.g.: http://google.com:80 => https://www.google.com:443
                this.AdditionalDestinations.Add($"https://www.{this.Destination.Host}:443");
            }
        }
    }

    public string GetContentType()
    {
        return "JMUX";
    }
}