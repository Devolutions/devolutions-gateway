using System.Buffers;
using System.Text;

namespace Devolutions.AgentIdentity;

/// <summary>
/// Reads the credential of an enroll request, <c>Authorization: Bearer &lt;token&gt;</c>.
/// </summary>
public static class EnrollmentAuthorization
{
    private const string TokenStart = EnrollmentToken.Prefix + ".";

    private static readonly SearchValues<char> Base64UrlAlphabet =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    /// <summary>
    /// Reads the enrollment token of an enroll request and returns the hash under which the authority finds it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The request gets <c>token_invalid</c> when the <c>Authorization</c> field is missing or repeated,
    /// does not use the <c>Bearer</c> scheme, or holds no <c>dvaet1</c> token of at most 4096 bytes.
    /// The scheme is case-insensitive, one or more spaces separate it from the token,
    /// and white space around the field value is ignored.
    /// </para>
    /// <para>
    /// The authority finds a token by its secret alone, so the bag is not decoded.
    /// When no stored token has <see cref="EnrollmentAuthorizationResult.SecretHash"/>,
    /// the request gets <c>token_invalid</c> too.
    /// Both checks come before any check of the request body.
    /// </para>
    /// </remarks>
    /// <param name="authorizationFieldLines">
    /// The values of the request's <c>Authorization</c> field lines, one per line as received, without combining them.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="authorizationFieldLines"/> is null.</exception>
    public static EnrollmentAuthorizationResult ReadBearerToken(IReadOnlyList<string> authorizationFieldLines)
    {
        ArgumentNullException.ThrowIfNull(authorizationFieldLines);

        if (authorizationFieldLines.Count == 0)
        {
            return EnrollmentAuthorizationResult.Failure("The request has no Authorization field.");
        }

        if (authorizationFieldLines.Count != 1)
        {
            return EnrollmentAuthorizationResult.Failure("The request has more than one Authorization field line.");
        }

        // RFC 9110 §5.5: the optional white space around a field value is not part of it.
        ReadOnlySpan<char> value = authorizationFieldLines[0].AsSpan().Trim(" \t");
        int separator = value.IndexOf(' ');
        ReadOnlySpan<char> scheme = separator < 0 ? value : value[..separator];

        if (!Ascii.EqualsIgnoreCase(scheme, "Bearer"))
        {
            return EnrollmentAuthorizationResult.Failure("The Authorization field does not use the Bearer scheme.");
        }

        if (separator < 0)
        {
            return EnrollmentAuthorizationResult.Failure("The Authorization field has no token after the Bearer scheme.");
        }

        ReadOnlySpan<char> token = value[separator..].TrimStart(' ');

        if (!(token.Length <= EnrollmentToken.MaxLength))
        {
            return EnrollmentAuthorizationResult.Failure("The bearer token is longer than 4096 bytes.");
        }

        if (!TryReadSecret(token, out ReadOnlySpan<char> secret))
        {
            return EnrollmentAuthorizationResult.Failure("The bearer token is not a dvaet1 enrollment token.");
        }

        return EnrollmentAuthorizationResult.Success(EnrollmentToken.HashSecret(secret));
    }

    // Matches the entire token, with nothing after the secret,
    // against the pattern of CONTRACT.md §2: ^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$.
    private static bool TryReadSecret(ReadOnlySpan<char> token, out ReadOnlySpan<char> secret)
    {
        secret = default;

        if (!token.StartsWith(TokenStart, StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> segments = token[TokenStart.Length..];
        int separator = segments.LastIndexOf('.');

        if (separator < 0)
        {
            return false;
        }

        ReadOnlySpan<char> bag = segments[..separator];
        secret = segments[(separator + 1)..];

        return 0 < bag.Length
            && secret.Length == EnrollmentToken.SecretLength
            && !bag.ContainsAnyExcept(Base64UrlAlphabet)
            && !secret.ContainsAnyExcept(Base64UrlAlphabet);
    }
}
