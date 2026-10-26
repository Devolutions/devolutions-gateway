using System.Globalization;
using System.Security.Cryptography;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Limits and encodings that every agent-facing endpoint shares.
/// </summary>
public static class AgentIdentityProtocol
{
    /// <summary>
    /// The largest request body, in bytes, that an agent-facing endpoint accepts.
    /// </summary>
    /// <remarks>
    /// A larger body gets <see cref="AgentIdentityError.BodyTooLarge"/> before any authentication.
    /// </remarks>
    public const int MaxRequestBodyBytes = 64 * 1024;

    /// <summary>
    /// Formats an instant as an RFC 3339 UTC timestamp in whole seconds, such as <c>2026-09-24T12:00:00Z</c>.
    /// </summary>
    /// <remarks>
    /// The fraction of a second is dropped.
    /// </remarks>
    /// <param name="value">The instant, in any offset.</param>
    public static string FormatTimestamp(DateTimeOffset value)
    {
        // The seconds specifier drops the fraction, so the timestamp names the second that contains the instant.
        return value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Computes the thumbprint of a certificate: <c>base64url(SHA-256(certificate DER))</c>, without padding.
    /// </summary>
    /// <remarks>
    /// A signed request names its certificate by this thumbprint in its <c>keyid</c> parameter.
    /// </remarks>
    /// <param name="certificateDer">The DER encoding of the certificate.</param>
    public static string ComputeThumbprint(ReadOnlySpan<byte> certificateDer)
    {
        return StrictBase64.EncodeBase64Url(SHA256.HashData(certificateDer));
    }
}
