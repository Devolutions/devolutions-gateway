

using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils
{
    public class JrlClaims : IGatewayClaims
    {
        [JsonPropertyName("jrl")]
        public IEnumerable<Guid> RevokedTokenList { get; set; }

        [JsonPropertyName("jet_gw_id")]
        public Guid ScopeGatewayId { get; set; }

        public JrlClaims(Guid scopeGatewayId, IEnumerable<Guid> revokedTokenList) 
        {
            this.RevokedTokenList = revokedTokenList;
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
}
