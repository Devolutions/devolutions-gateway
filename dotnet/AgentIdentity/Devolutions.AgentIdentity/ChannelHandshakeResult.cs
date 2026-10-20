using System.Diagnostics.CodeAnalysis;

using Devolutions.Agent.Channel.V1;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of the handshake that authenticates an agent channel stream:
/// the identity that the agent proved, with its metadata and the <c>Welcome</c> to send,
/// or the error that closes the stream.
/// </summary>
/// <remarks>
/// On success, the host replaces the identity's metadata with <see cref="Metadata"/>, sends <see cref="Welcome"/>,
/// and only then treats the stream as authenticated.
/// On failure, the host closes the stream with <see cref="AgentIdentityError.ToRpcException"/> of <see cref="Error"/>,
/// and changes no state of the identity.
/// </remarks>
public sealed class ChannelHandshakeResult
{
    private ChannelHandshakeResult(
        AuthenticatedIdentity? identity,
        AgentMetadata? metadata,
        ServerMessage? welcome,
        AgentIdentityError? error,
        string? failureDetail)
    {
        Succeeded = identity is not null;
        Identity = identity;
        Metadata = metadata;
        Welcome = welcome;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the agent proved that it holds the key of the certificate that opened the stream,
    /// and sent valid metadata.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Identity), nameof(Metadata), nameof(Welcome))]
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The identity that the stream is authenticated for, with <see cref="AgentOperation.Connect"/>,
    /// when the handshake succeeded.
    /// </summary>
    /// <remarks>
    /// The stream stays bound to the certificate that opened it,
    /// so the host closes the stream no later than <see cref="AuthenticatedIdentity.CertificateNotAfter"/>.
    /// </remarks>
    public AuthenticatedIdentity? Identity { get; }

    /// <summary>
    /// The metadata of the <c>Hello</c>, which replaces the identity's metadata, when the handshake succeeded.
    /// </summary>
    public AgentMetadata? Metadata { get; }

    /// <summary>
    /// The <c>Welcome</c> that answers the <c>Hello</c>, when the handshake succeeded:
    /// a fresh <c>id</c>, the <c>Hello</c> <c>id</c> as <c>correlation_id</c>, and the server time.
    /// </summary>
    public ServerMessage? Welcome { get; }

    /// <summary>
    /// The error to close the stream with, when the handshake failed:
    /// <see cref="AgentIdentityErrorCode.SignatureInvalid"/> when the agent did not prove the key in time,
    /// or <see cref="AgentIdentityErrorCode.InvalidRequest"/> when its proof verified but its metadata is invalid.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// The rule that the first agent message broke, for host logs, when the handshake failed.
    /// </summary>
    /// <remarks>
    /// It never repeats a value from the message, and quotes a metadata key only when the key itself is valid.
    /// </remarks>
    public string? FailureDetail { get; }

    internal static ChannelHandshakeResult Success(
        AuthenticatedIdentity identity,
        AgentMetadata metadata,
        ServerMessage welcome)
    {
        return new ChannelHandshakeResult(identity, metadata, welcome, null, null);
    }

    internal static ChannelHandshakeResult Failure(AgentIdentityError error, string failureDetail)
    {
        return new ChannelHandshakeResult(null, null, null, error, failureDetail);
    }
}
