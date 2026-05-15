using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class ProvisionCredentialsRequest
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }

    [JsonPropertyName("kind")]
    public string Kind => "provision-credentials";

    [JsonPropertyName("token")]
    public string Token { get; set; }

    [JsonPropertyName("proxy_credential")]
    public CleartextCredential ProxyCredential { get; set; }

    [JsonPropertyName("target_credential")]
    public CleartextCredential TargetCredential { get; set; }

    [JsonPropertyName("time_to_live")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? TimeToLive { get; set; }

    public ProvisionCredentialsRequest(
        Guid id,
        string token,
        CleartextCredential proxyCredential,
        CleartextCredential targetCredential,
        uint? timeToLive = null)
    {
        this.Id = id;
        this.Token = token;
        this.ProxyCredential = proxyCredential;
        this.TargetCredential = targetCredential;
        this.TimeToLive = timeToLive;
    }
}

public class CleartextCredential
{
    [JsonPropertyName("kind")]
    public string Kind => "username-password";

    [JsonPropertyName("username")]
    public string Username { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }

    public CleartextCredential(string username, string password)
    {
        this.Username = username;
        this.Password = password;
    }
}
