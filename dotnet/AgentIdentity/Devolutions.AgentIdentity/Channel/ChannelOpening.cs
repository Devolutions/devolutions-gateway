using System.Diagnostics.CodeAnalysis;

using Devolutions.Agent.Channel.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

using ChallengePayload = Devolutions.Agent.Channel.V1.Challenge;
using WelcomePayload = Devolutions.Agent.Channel.V1.Welcome;

namespace Devolutions.AgentIdentity;

/// <summary>
/// An agent channel stream whose signed opening request verified, before the agent proves it holds the key.
/// </summary>
/// <remarks>
/// Signed opening headers are not tied to one stream and can be captured on the way,
/// so they never authenticate a stream on their own.
/// The host sends <see cref="Challenge"/> as the first message on the stream,
/// and the stream is authenticated only once the agent signs that challenge.
/// The identity stays hidden until then, so that nothing acts for it on the strength of the headers alone.
/// The host passes the first agent message to <see cref="VerifyHelloAsync"/>,
/// calls <see cref="FirstMessageUnreadableAsync"/> when it cannot decode that message,
/// or calls <see cref="HelloTimedOutAsync"/> when none arrives within <see cref="ChannelHandshake.HelloTimeout"/>.
/// </remarks>
public sealed class ChannelOpening
{
    private const string ExpiredDetail = "The certificate that opened the stream expired during the handshake.";

    private static readonly AgentIdentityError SignatureInvalid =
        AgentIdentityError.From(AgentIdentityErrorCode.SignatureInvalid);

    private static readonly AgentIdentityError CertificateExpired =
        AgentIdentityError.From(AgentIdentityErrorCode.CertificateExpired);

    private static readonly AgentIdentityError IdentityUnknown =
        AgentIdentityError.From(AgentIdentityErrorCode.IdentityUnknown);

    private static readonly AgentIdentityError IdentityRevoked =
        AgentIdentityError.From(AgentIdentityErrorCode.IdentityRevoked);

    private readonly TimeProvider _timeProvider;
    private readonly ICertificateRegistry _certificateRegistry;

    // Set by the first call to VerifyHelloAsync, HelloTimedOutAsync or FirstMessageUnreadableAsync.
    private int _handshakeEnded;

    internal ChannelOpening(
        VerifiedCertificate certificate,
        string connectNonce,
        Guid challengeId,
        byte[] challenge,
        DateTimeOffset openedAt,
        TimeProvider timeProvider,
        ICertificateRegistry certificateRegistry)
    {
        Certificate = certificate;
        ConnectNonce = connectNonce;
        ChallengeId = challengeId.ToString("D");
        ChallengeBytes = challenge;
        Challenge = new ServerMessage
        {
            Id = ChallengeId,
            Challenge = new ChallengePayload { Challenge_ = ByteString.CopyFrom(challenge) },
        };
        OpenedAt = openedAt;
        _timeProvider = timeProvider;
        _certificateRegistry = certificateRegistry;
    }

    /// <summary>
    /// The first message to send on the stream: a <c>Challenge</c> with 32 random bytes fresh for this stream.
    /// </summary>
    public ServerMessage Challenge { get; }

    /// <summary>
    /// The thumbprint of the certificate that signed the opening request,
    /// for logs and to key the stream among the host's live streams until the handshake reveals the identity.
    /// </summary>
    /// <remarks>
    /// The host adds the stream under this thumbprint to the live streams that its revocation and deletion paths
    /// close before it ends the handshake, so that a revocation that commits after the handshake's registry read
    /// still finds and closes the stream.
    /// </remarks>
    public string CertificateThumbprint => Certificate.Thumbprint;

    /// <summary>
    /// The <c>notAfter</c> of the certificate that signed the opening request.
    /// </summary>
    /// <remarks>
    /// Once this time has passed, the host closes a stream still waiting for its <c>Hello</c> with the error of
    /// <see cref="HelloTimedOutAsync"/>: <see cref="AgentIdentityErrorCode.CertificateExpired"/>, which that method
    /// returns only strictly after this time, unless the identity is also revoked or deleted.
    /// It is a time, not an identity, which stays hidden until the agent signs the challenge.
    /// </remarks>
    public DateTimeOffset CertificateNotAfter => Certificate.NotAfter;

    /// <summary>
    /// The certificate that signed the opening request, whose key must also sign the challenge.
    /// </summary>
    internal VerifiedCertificate Certificate { get; }

    /// <summary>
    /// The <c>nonce</c> parameter of the opening request, whose UTF-8 bytes end the signed challenge.
    /// </summary>
    internal string ConnectNonce { get; }

    /// <summary>
    /// The <c>id</c> of <see cref="Challenge"/>, as sent.
    /// </summary>
    internal string ChallengeId { get; }

    /// <summary>
    /// The random bytes of <see cref="Challenge"/>, as sent.
    /// </summary>
    /// <remarks>
    /// They are kept apart from the message,
    /// so that a change to the message object cannot change what the agent must sign.
    /// </remarks>
    internal ReadOnlyMemory<byte> ChallengeBytes { get; }

    /// <summary>
    /// The instant the opening request was verified,
    /// from which the agent has <see cref="ChannelHandshake.HelloTimeout"/> to answer the challenge.
    /// </summary>
    internal DateTimeOffset OpenedAt { get; }

    /// <summary>
    /// Verifies the first message that the agent sent on the stream,
    /// as CONTRACT.agent-identity.md §7.3 step 4 specifies.
    /// </summary>
    /// <remarks>
    /// The method reads the clock once, then the certificate registry once,
    /// because the host cannot close the stream for a change to its identity while that identity is still hidden.
    /// In the order of CONTRACT.agent-identity.md §6 step 4, the handshake fails with
    /// <see cref="AgentIdentityErrorCode.IdentityUnknown"/> when the certificate that opened the stream is no longer
    /// registered or its identity was deleted, with <see cref="AgentIdentityErrorCode.IdentityRevoked"/> when the
    /// identity is revoked, and with <see cref="AgentIdentityErrorCode.CertificateExpired"/> after
    /// <see cref="CertificateNotAfter"/>.
    /// A certificate retired since the opening still passes,
    /// and <see cref="AuthenticatedIdentity.CertificateStatus"/> then reports <see cref="CertificateStatus.Retired"/>;
    /// CONTRACT.agent-identity.md §7.4 says how the host treats a stream of a retired certificate.
    /// More than <see cref="ChannelHandshake.HelloTimeout"/> after the opening request was verified,
    /// the handshake fails with <see cref="AgentIdentityErrorCode.SignatureInvalid"/>,
    /// even when the host's own timer let the message through.
    /// The message must then be a <c>Hello</c> whose <c>correlation_id</c> is the <c>id</c> of <see cref="Challenge"/>,
    /// and whose <c>proof</c> verifies with the key of the certificate that signed the opening request;
    /// otherwise the handshake fails with <see cref="AgentIdentityErrorCode.SignatureInvalid"/>.
    /// Only then is the metadata checked, and metadata that CONTRACT.agent-identity.md §3 rejects fails the handshake
    /// with <see cref="AgentIdentityErrorCode.InvalidRequest"/>.
    /// The <c>Welcome</c> of a successful handshake carries the time of the clock reading.
    /// The first call to this method, to <see cref="HelloTimedOutAsync"/>
    /// or to <see cref="FirstMessageUnreadableAsync"/> ends the handshake, whatever its outcome,
    /// including an exception from the registry, which propagates.
    /// </remarks>
    /// <param name="firstMessage">The first message that the agent sent on the stream.</param>
    /// <param name="cancellationToken">A token that cancels the registry lookup.</param>
    /// <exception cref="ArgumentNullException"><paramref name="firstMessage"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The handshake has already ended,
    /// or the registry returned another certificate, or the certificate for another identity.
    /// </exception>
    public async ValueTask<ChannelHandshakeResult> VerifyHelloAsync(
        AgentMessage firstMessage,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(firstMessage);
        EndHandshake();

        (DateTimeOffset now, RegisteredCertificate? registered) =
            await ReadClockAndRegistryAsync(cancellationToken).ConfigureAwait(false);

        if (IsClosed(registered, now, out ChannelHandshakeResult? closure))
        {
            return closure;
        }

        if (now - OpenedAt > ChannelHandshake.HelloTimeout)
        {
            return ChannelHandshakeResult.Failure(SignatureInvalid, "The Hello arrived after the timeout.");
        }

        if (firstMessage.PayloadCase != AgentMessage.PayloadOneofCase.Hello)
        {
            return ChannelHandshakeResult.Failure(SignatureInvalid, "The first message on the stream is not a Hello.");
        }

        if (!firstMessage.HasCorrelationId)
        {
            return ChannelHandshakeResult.Failure(SignatureInvalid, "The Hello has no correlation_id.");
        }

        if (!string.Equals(firstMessage.CorrelationId, ChallengeId, StringComparison.Ordinal))
        {
            return ChannelHandshakeResult.Failure(
                SignatureInvalid,
                "The correlation_id of the Hello is not the id of the Challenge.");
        }

        Hello hello = firstMessage.Hello;

        if (!ChannelProof.Verify(Certificate.SubjectPublicKeyInfo, ChallengeBytes.Span, ConnectNonce, hello.Proof.Span))
        {
            return ChannelHandshakeResult.Failure(
                SignatureInvalid,
                "The proof of the Hello does not verify with the key of the certificate that opened the stream.");
        }

        MetadataValidationResult metadata = AgentMetadata.Validate(hello.Metadata);
        if (!metadata.Succeeded)
        {
            return ChannelHandshakeResult.Failure(metadata.Error, metadata.FailureDetail);
        }

        ServerMessage welcome = new()
        {
            Id = Guid.NewGuid().ToString("D"),
            CorrelationId = firstMessage.Id,
            Welcome = new WelcomePayload { ServerTime = Timestamp.FromDateTimeOffset(now) },
        };

        return ChannelHandshakeResult.Success(
            (Certificate with { Status = registered.Status }).ToIdentity(AgentOperation.Connect),
            metadata.Metadata,
            welcome);
    }

    /// <summary>
    /// Ends the handshake of a stream on which no agent message arrived within
    /// <see cref="ChannelHandshake.HelloTimeout"/>.
    /// </summary>
    /// <remarks>
    /// A stream still awaiting its <c>Hello</c> closes for its identity and its certificate before it closes for the
    /// timeout, so the method reads the clock once, then the certificate registry once, as
    /// <see cref="VerifyHelloAsync"/> does.
    /// In the order of CONTRACT.agent-identity.md §6 step 4, the handshake fails with
    /// <see cref="AgentIdentityErrorCode.IdentityUnknown"/> when the certificate that opened the stream is no longer
    /// registered or its identity was deleted, with <see cref="AgentIdentityErrorCode.IdentityRevoked"/> when the
    /// identity is revoked, and with <see cref="AgentIdentityErrorCode.CertificateExpired"/> after
    /// <see cref="CertificateNotAfter"/>.
    /// Otherwise it fails with <see cref="AgentIdentityErrorCode.SignatureInvalid"/>.
    /// The host also calls it when the agent ends the stream without sending a message.
    /// The first call to this method, to <see cref="VerifyHelloAsync"/>
    /// or to <see cref="FirstMessageUnreadableAsync"/> ends the handshake, whatever its outcome,
    /// including an exception from the registry, which propagates.
    /// </remarks>
    /// <param name="cancellationToken">A token that cancels the registry lookup.</param>
    /// <exception cref="InvalidOperationException">
    /// The handshake has already ended,
    /// or the registry returned another certificate, or the certificate for another identity.
    /// </exception>
    public async ValueTask<ChannelHandshakeResult> HelloTimedOutAsync(CancellationToken cancellationToken = default)
    {
        EndHandshake();

        return await FailWithoutHelloAsync("No Hello arrived before the timeout.", cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Ends the handshake of a stream whose first agent message could not be decoded.
    /// </summary>
    /// <remarks>
    /// The host calls it when the transport cannot decode the first <c>AgentMessage</c>,
    /// for example because a protobuf <c>string</c> holds invalid UTF-8, so that no message exists to pass to
    /// <see cref="VerifyHelloAsync"/>.
    /// No proof can be read from such a message, so CONTRACT.agent-identity.md §7.3 step 4 counts it as not a
    /// <c>Hello</c>.
    /// Like <see cref="HelloTimedOutAsync"/>, the method reads the clock once, then the certificate registry once,
    /// and fails the handshake for the certificate and its identity as that method does.
    /// Otherwise it fails with <see cref="AgentIdentityErrorCode.SignatureInvalid"/>.
    /// The first call to this method, to <see cref="VerifyHelloAsync"/>
    /// or to <see cref="HelloTimedOutAsync"/> ends the handshake, whatever its outcome,
    /// including an exception from the registry, which propagates.
    /// </remarks>
    /// <param name="cancellationToken">A token that cancels the registry lookup.</param>
    /// <exception cref="InvalidOperationException">
    /// The handshake has already ended,
    /// or the registry returned another certificate, or the certificate for another identity.
    /// </exception>
    public async ValueTask<ChannelHandshakeResult> FirstMessageUnreadableAsync(
        CancellationToken cancellationToken = default)
    {
        EndHandshake();

        return await FailWithoutHelloAsync("The first message on the stream could not be decoded.", cancellationToken)
            .ConfigureAwait(false);
    }

    private void EndHandshake()
    {
        // UNTESTED: of two calls racing on two threads, exactly one ends the handshake and the other throws.
        // A host can receive the first message just as its Hello timer fires,
        // and both calls deciding the stream could authenticate a stream that is being closed.
        // When changing this guard, keep the read and the write of the flag in one atomic operation.
        if (Interlocked.Exchange(ref _handshakeEnded, 1) != 0)
        {
            throw new InvalidOperationException("The handshake of this channel opening has already ended.");
        }
    }

    // CONTRACT.agent-identity.md §6: a certificate is unexpired while now ≤ notAfter.
    private bool HasExpired(DateTimeOffset now)
    {
        return now > Certificate.NotAfter;
    }

    // Reads the clock, then the registry, once each.
    // The clock comes first, as in CONTRACT.agent-identity.md §6, so that a slow registry cannot make a Hello late.
    // The host cannot tie the stream to its identity before the proof verifies,
    // so only this lookup sees a revocation, a deletion or a rotation since the opening.
    private async ValueTask<(DateTimeOffset Now, RegisteredCertificate? Registered)> ReadClockAndRegistryAsync(
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        RegisteredCertificate? registered = await _certificateRegistry
            .FindByThumbprintAsync(Certificate.Thumbprint, cancellationToken)
            .ConfigureAwait(false);

        return (now, registered);
    }

    // The outcome of a handshake with no Hello to verify: the closure that applies, if any,
    // and otherwise signature_invalid with the detail, as CONTRACT.agent-identity.md §7.3 step 4 specifies.
    private async ValueTask<ChannelHandshakeResult> FailWithoutHelloAsync(
        string detail,
        CancellationToken cancellationToken)
    {
        (DateTimeOffset now, RegisteredCertificate? registered) =
            await ReadClockAndRegistryAsync(cancellationToken).ConfigureAwait(false);

        return IsClosed(registered, now, out ChannelHandshakeResult? closure)
            ? closure
            : ChannelHandshakeResult.Failure(SignatureInvalid, detail);
    }

    // CONTRACT.agent-identity.md §7.4: a deletion, a revocation and the certificate's notAfter close a stream even
    // while it awaits its Hello, ahead of every failure of §7.3 step 4, in the order of §6 step 4.
    // A certificate retired since the opening does not close the stream:
    // §7.4 lets that stream complete the handshake, whereas identity_unknown would end the identity for an agent
    // that did nothing wrong.
    private bool IsClosed(
        [NotNullWhen(false)] RegisteredCertificate? registered,
        DateTimeOffset now,
        [NotNullWhen(true)] out ChannelHandshakeResult? closure)
    {
        if (registered is null)
        {
            closure = ChannelHandshakeResult.Failure(
                IdentityUnknown,
                "The certificate that opened the stream is no longer registered, or its identity was deleted.");
            return true;
        }

        CheckIsTheOpeningCertificate(registered);

        if (registered.IdentityRevoked)
        {
            closure = ChannelHandshakeResult.Failure(
                IdentityRevoked,
                "The identity was revoked after the stream opened.");
            return true;
        }

        if (HasExpired(now))
        {
            closure = ChannelHandshakeResult.Failure(CertificateExpired, ExpiredDetail);
            return true;
        }

        closure = null;
        return false;
    }

    // The registry answers a thumbprint with the certificate that the authority issued under it, for its one identity,
    // so another answer is a host bug, which fails as a server error rather than as a verdict on the agent.
    private void CheckIsTheOpeningCertificate(RegisteredCertificate registered)
    {
        if (AgentIdentityProtocol.ComputeThumbprint(registered.CertificateDer.Span) != Certificate.Thumbprint)
        {
            throw new InvalidOperationException(
                "The certificate registry returned a certificate whose thumbprint is not the one it was asked for.");
        }

        if (registered.IdentityId != Certificate.IdentityId)
        {
            throw new InvalidOperationException(
                "The certificate registry returned the certificate that opened the stream for another identity.");
        }
    }
}
