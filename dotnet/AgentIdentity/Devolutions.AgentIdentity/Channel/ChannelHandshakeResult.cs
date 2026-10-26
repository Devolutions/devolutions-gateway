using System.Diagnostics.CodeAnalysis;

using Devolutions.Agent.Channel.V1;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of the handshake that authenticates an agent channel stream:
/// the identity that the agent proved, with its metadata and the <c>Welcome</c> to send,
/// or the error that closes the stream.
/// </summary>
/// <remarks>
/// <para>
/// On success, the host replaces the identity's metadata with <see cref="Metadata"/>, sends <see cref="Welcome"/>,
/// and only then treats the stream as authenticated.
/// On failure, the host closes the stream with <see cref="AgentIdentityError.ToRpcException"/> of
/// <see cref="AgentIdentityResult.Error"/>, and changes no state of the identity.
/// </para>
/// <para>
/// The error is <see cref="AgentIdentityErrorCode.IdentityUnknown"/> when the certificate that opened the stream is
/// no longer registered or its identity was deleted, <see cref="AgentIdentityErrorCode.IdentityRevoked"/> when the
/// identity was revoked, <see cref="AgentIdentityErrorCode.CertificateExpired"/> when the certificate expired
/// during the handshake, and <see cref="AgentIdentityErrorCode.InvalidRequest"/> when the agent proved the key in
/// time but sent invalid metadata.
/// Every other failure is <see cref="AgentIdentityErrorCode.SignatureInvalid"/>.
/// <see cref="AgentIdentityResult.FailureDetail"/> never repeats a value from the message, not even a metadata key:
/// it names a metadata entry by its position.
/// </para>
/// </remarks>
public sealed class ChannelHandshakeResult : AgentIdentityResult
{
    private ChannelHandshakeResult(
        AuthenticatedIdentity? identity,
        AgentMetadata? metadata,
        ServerMessage? welcome,
        AgentIdentityError? error,
        string? failureDetail)
        : base(error, failureDetail)
    {
        Identity = identity;
        Metadata = metadata;
        Welcome = welcome;
    }

    /// <summary>
    /// Whether the stream authenticated: the certificate that opened it is still registered, unexpired and of an
    /// unrevoked identity, and the agent proved in time that it holds its key and sent valid metadata.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Identity), nameof(Metadata), nameof(Welcome))]
    public override bool Succeeded => Identity is not null && Metadata is not null && Welcome is not null;

    /// <summary>
    /// The identity that the stream is authenticated for, with <see cref="AgentOperation.Connect"/>,
    /// when the handshake succeeded.
    /// </summary>
    /// <remarks>
    /// The stream stays bound to the certificate that opened it,
    /// so the host closes the stream no later than <see cref="AuthenticatedIdentity.CertificateNotAfter"/>.
    /// When that certificate was retired during the handshake,
    /// <see cref="AuthenticatedIdentity.CertificateStatus"/> is <see cref="CertificateStatus.Retired"/>,
    /// and CONTRACT.agent-identity.md §7.4 says how the host treats a stream of a retired certificate.
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
