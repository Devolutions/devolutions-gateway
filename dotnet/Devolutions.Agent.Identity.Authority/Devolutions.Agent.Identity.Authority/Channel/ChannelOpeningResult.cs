using System.Diagnostics.CodeAnalysis;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The outcome of authenticating the signed opening request of an agent channel stream.
/// </summary>
/// <remarks>
/// When the opening fails, the host closes the stream with <see cref="AgentIdentityError.ToRpcException"/> of
/// <see cref="AgentIdentityResult.Error"/>.
/// <see cref="AgentIdentityResult.FailureDetail"/> names the rule that the opening request broke and the step of
/// CONTRACT.agent-identity.md §6 that checks it.
/// </remarks>
public sealed class ChannelOpeningResult : AgentIdentityResult
{
    private ChannelOpeningResult(ChannelOpening? opening, AgentIdentityError? error, string? failureDetail)
        : base(error, failureDetail)
    {
        Opening = opening;
    }

    /// <summary>
    /// Whether the opening request authenticated.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Opening))]
    public override bool Succeeded => Opening is not null;

    /// <summary>
    /// The opened stream, waiting for the agent to sign its challenge, when the opening request authenticated.
    /// </summary>
    public ChannelOpening? Opening { get; }

    internal static ChannelOpeningResult Success(ChannelOpening opening)
    {
        return new ChannelOpeningResult(opening, null, null);
    }

    internal static ChannelOpeningResult Failure(AgentIdentityError error, string failureDetail)
    {
        return new ChannelOpeningResult(null, error, failureDetail);
    }
}
