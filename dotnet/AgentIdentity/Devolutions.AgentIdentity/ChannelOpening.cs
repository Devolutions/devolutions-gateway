using Devolutions.Agent.Channel.V1;
using Google.Protobuf;

using ChallengePayload = Devolutions.Agent.Channel.V1.Challenge;

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
/// </remarks>
public sealed class ChannelOpening
{
    internal ChannelOpening(VerifiedCertificate certificate, string connectNonce, Guid challengeId, byte[] challenge)
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
    }

    /// <summary>
    /// The first message to send on the stream: a <c>Challenge</c> with 32 random bytes fresh for this stream.
    /// </summary>
    public ServerMessage Challenge { get; }

    /// <summary>
    /// The thumbprint of the certificate that signed the opening request, for logs.
    /// </summary>
    public string CertificateThumbprint => Certificate.Thumbprint;

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
}
