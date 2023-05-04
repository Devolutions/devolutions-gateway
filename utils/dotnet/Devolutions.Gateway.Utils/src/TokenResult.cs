namespace Devolutions.Gateway.Utils;

public class TokenResult
{
    public string Token { get; set; }

    public long IssuedAt { get; set; }

    public Guid JwtId { get; set; }

    public long? NotBefore { get; set; }

    public long? Expiration { get; set; }

    internal TokenResult(string token, long issuedAt, Guid jwtId, long? notBefore, long? expiration)
    {
        Token = token;
        IssuedAt = issuedAt;
        JwtId = jwtId;
        NotBefore = notBefore;
        Expiration = expiration;
    }
}