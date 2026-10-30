using System.Diagnostics.CodeAnalysis;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The outcome of a check of the library: success with the values that the derived type names,
/// or the error to respond with and a detail for host logs.
/// </summary>
/// <remarks>
/// After <see cref="Succeeded"/> is false, <see cref="Error"/> and <see cref="FailureDetail"/> are not null;
/// after it is true, the values of the derived type are not null.
/// </remarks>
public abstract class AgentIdentityResult
{
    private protected AgentIdentityResult(AgentIdentityError? error, string? failureDetail)
    {
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the check succeeded.
    /// </summary>
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public virtual bool Succeeded => Error is null;

    /// <summary>
    /// The error to respond with, when <see cref="Succeeded"/> is false; otherwise null.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// The rule that the check failed on, for host logs, when <see cref="Succeeded"/> is false; otherwise null.
    /// </summary>
    /// <remarks>
    /// It never holds a value taken from the request, such as a metadata key or value, a header, signature data
    /// or a token.
    /// </remarks>
    public string? FailureDetail { get; }
}
