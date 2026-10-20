using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of authenticating a signed request.
/// </summary>
public sealed class AuthenticationResult
{
    private AuthenticationResult(AuthenticatedIdentity? identity, AgentIdentityError? error, string? failureDetail)
    {
        Succeeded = identity is not null;
        Identity = identity;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the request authenticated.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Identity))]
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The identity that the request proved, when it authenticated.
    /// </summary>
    public AuthenticatedIdentity? Identity { get; }

    /// <summary>
    /// The error to respond with, when the request did not authenticate.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// The rule that the request broke and the step of CONTRACT.md §6 that checks it, for host logs.
    /// </summary>
    /// <remarks>
    /// It is a fixed sentence, so it never holds a header value, a token or a secret.
    /// </remarks>
    public string? FailureDetail { get; }

    internal static AuthenticationResult Success(AuthenticatedIdentity identity)
    {
        return new AuthenticationResult(identity, null, null);
    }

    internal static AuthenticationResult Failure(AgentIdentityError error, string failureDetail)
    {
        return new AuthenticationResult(null, error, failureDetail);
    }
}
