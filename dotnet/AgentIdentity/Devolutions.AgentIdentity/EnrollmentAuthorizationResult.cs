using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The result of <see cref="EnrollmentAuthorization.ReadBearerToken"/>:
/// the hash under which the authority finds the enrollment token, or <c>token_invalid</c>.
/// </summary>
public sealed class EnrollmentAuthorizationResult
{
    private EnrollmentAuthorizationResult(
        ReadOnlyMemory<byte> secretHash,
        AgentIdentityError? error,
        string? failureDetail)
    {
        Succeeded = error is null;
        SecretHash = secretHash;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the request holds a well-formed token.
    /// </summary>
    /// <remarks>
    /// A well-formed token still authenticates nothing until the authority finds a stored token by its hash.
    /// </remarks>
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The SHA-256 of the ASCII text of the token's secret,
    /// which is the <see cref="EnrollmentToken.SecretHash"/> of the stored token;
    /// empty when <see cref="Succeeded"/> is false.
    /// </summary>
    public ReadOnlyMemory<byte> SecretHash { get; }

    /// <summary>
    /// <c>token_invalid</c>, with HTTP status 401, when <see cref="Succeeded"/> is false; otherwise null.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// Why the request holds no well-formed token, for the host's logs, when <see cref="Succeeded"/> is false;
    /// otherwise null.
    /// </summary>
    /// <remarks>
    /// The detail is a fixed sentence and never holds any part of the token.
    /// </remarks>
    public string? FailureDetail { get; }

    internal static EnrollmentAuthorizationResult Success(byte[] secretHash)
    {
        return new EnrollmentAuthorizationResult(secretHash, null, null);
    }

    internal static EnrollmentAuthorizationResult Failure(string failureDetail)
    {
        return new EnrollmentAuthorizationResult(
            ReadOnlyMemory<byte>.Empty,
            AgentIdentityError.From(AgentIdentityErrorCode.TokenInvalid),
            failureDetail);
    }
}
