using System.Text.Json;
using System.Text.Json.Nodes;

namespace Devolutions.Gateway.Utils;

public static class TokenUtils
{
    public static string Sign<T>(T claims, Picky.PrivateKey signKey, string? keyId, long? lifetime) where T : IGatewayClaims
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

        long IssuedAt = now;
        Guid JwtId = Guid.NewGuid();
        long? NotBefore = null;
        long? Expiration = null;

        if (lifetime != null)
        {
            NotBefore = now;
            Expiration = now + lifetime;
        }

        JsonNode? body = JsonSerializer.SerializeToNode(claims);

        if (body == null)
        {
            throw new Exception("Unexpected error when serializing claims");
        }

        body["iat"] = IssuedAt;
        body["jti"] = JwtId;

        if (NotBefore != null)
        {
            body["nbf"] = NotBefore;
        }

        if (Expiration != null)
        {
            body["exp"] = Expiration;
        }

        builder.Claims = body.ToJsonString();

        Picky.JwtSig token = builder.Build();

        return token.Encode(signKey);
    }

    public static string Sign<T>(T claims, Picky.PrivateKey signKey) where T : IGatewayClaims
    {
        return Sign(claims, signKey, null, null);
    }

    public static string Sign<T>(T claims, Picky.PrivateKey signKey, string keyId) where T : IGatewayClaims
    {
        return Sign(claims, signKey, keyId, null);
    }
}