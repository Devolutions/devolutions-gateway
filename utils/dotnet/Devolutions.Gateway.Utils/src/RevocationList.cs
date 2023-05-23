using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils
{
    public class RevocationList
    {
        [JsonPropertyName("jti")]
        public IEnumerable<Guid> JtiValues { get; set; }

        public RevocationList(IEnumerable<Guid> jtiValues)
        {
            this.JtiValues = jtiValues;
        }
    }
}