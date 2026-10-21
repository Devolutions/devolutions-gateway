using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of authenticating the signed opening request of an agent channel stream.
/// </summary>
/// <remarks>
/// When the opening fails, the host closes the stream with <see cref="AgentIdentityError.ToRpcException"/> of
/// <see cref="Error"/>.
/// </remarks>
public sealed class ChannelOpeningResult
{
    private ChannelOpeningResult(ChannelOpening? opening, AgentIdentityError? error, string? failureDetail)
    {
        Succeeded = opening is not null;
        Opening = opening;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the opening request authenticated.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Opening))]
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The opened stream, waiting for the agent to sign its challenge, when the opening request authenticated.
    /// </summary>
    public ChannelOpening? Opening { get; }

    /// <summary>
    /// The error to close the stream with, when the opening request did not authenticate.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// The rule that the opening request broke and the step of CONTRACT.agent-identity.md §6 that checks it,
    /// for host logs.
    /// </summary>
    /// <remarks>
    /// It is a fixed sentence, so it never holds a header value, a token or a secret.
    /// </remarks>
    public string? FailureDetail { get; }

    internal static ChannelOpeningResult Success(ChannelOpening opening)
    {
        return new ChannelOpeningResult(opening, null, null);
    }

    internal static ChannelOpeningResult Failure(AgentIdentityError error, string failureDetail)
    {
        return new ChannelOpeningResult(null, error, failureDetail);
    }
}
