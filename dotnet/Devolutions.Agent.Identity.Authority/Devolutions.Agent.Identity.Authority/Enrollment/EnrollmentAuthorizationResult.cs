namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The result of <see cref="EnrollmentAuthorization.ReadBearerToken"/>:
/// the hash under which the authority finds the enrollment token, or <c>token_invalid</c>.
/// </summary>
/// <remarks>
/// <see cref="AgentIdentityResult.Succeeded"/> tells whether the request holds a well-formed token,
/// which still authenticates nothing until the authority finds a stored token by its hash.
/// The error is <c>token_invalid</c>, with HTTP status 401,
/// and <see cref="AgentIdentityResult.FailureDetail"/> is a fixed sentence that never holds any part of the token.
/// </remarks>
public sealed class EnrollmentAuthorizationResult : AgentIdentityResult
{
    private EnrollmentAuthorizationResult(
        ReadOnlyMemory<byte> secretHash,
        AgentIdentityError? error,
        string? failureDetail)
        : base(error, failureDetail)
    {
        SecretHash = secretHash;
    }

    /// <summary>
    /// The SHA-256 of the 32 bytes that the token's secret encodes,
    /// which is the <see cref="EnrollmentToken.SecretHash"/> of the stored token;
    /// empty when <see cref="AgentIdentityResult.Succeeded"/> is false.
    /// </summary>
    public ReadOnlyMemory<byte> SecretHash { get; }

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
