using System.Text.Json;
using System.Text.Json.Nodes;

namespace Devolutions.Gateway.Utils;

public static class TokenUtils
{
    public static TokenResult Sign<T>(T claims, Picky.PrivateKey signKey, string? keyId = null, long? lifetime = null) where T : IGatewayClaims
    {
        Picky.JwtSigBuilder builder = Picky.JwtSig.Builder();
        builder.ContentType = claims.GetContentType();

        if (keyId != null)
        {
            builder.Kid = keyId;
        }

        if (lifetime == null)
        {
            lifetime = claims.GetDefaultLifetime();
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        long issuedAt = now;
        Guid jwtId = Guid.NewGuid();
        long? notBefore = null;
        long? expiration = null;

        if (lifetime != null)
        {
            notBefore = now;
            expiration = now + lifetime;
        }

        JsonNode? body = JsonSerializer.SerializeToNode(claims);

        if (body == null)
        {
            throw new Exception("Unexpected error when serializing claims");
        }

        body["iat"] = issuedAt;
        body["jti"] = jwtId;

        if (notBefore != null)
        {
            body["nbf"] = notBefore;
        }

        if (expiration != null)
        {
            body["exp"] = expiration;
        }

        builder.Claims = body.ToJsonString();

        Picky.JwtSig token = builder.Build();

        string encodedToken = token.Encode(signKey);

        return new(encodedToken, issuedAt, jwtId, notBefore, expiration);
    }
}