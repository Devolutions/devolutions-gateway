using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of authenticating a signed request.
/// </summary>
/// <remarks>
/// <see cref="AgentIdentityResult.FailureDetail"/> names the rule that the request broke and the step of
/// CONTRACT.agent-identity.md §6 that checks it.
/// </remarks>
public sealed class AuthenticationResult : AgentIdentityResult
{
    private AuthenticationResult(AuthenticatedIdentity? identity, AgentIdentityError? error, string? failureDetail)
        : base(error, failureDetail)
    {
        Identity = identity;
    }

    /// <summary>
    /// Whether the request authenticated.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Identity))]
    public override bool Succeeded => Identity is not null;

    /// <summary>
    /// The identity that the request proved, when it authenticated.
    /// </summary>
    public AuthenticatedIdentity? Identity { get; }

    internal static AuthenticationResult Success(AuthenticatedIdentity identity)
    {
        return new AuthenticationResult(identity, null, null);
    }

    internal static AuthenticationResult Failure(AgentIdentityError error, string failureDetail)
    {
        return new AuthenticationResult(null, error, failureDetail);
    }
}
