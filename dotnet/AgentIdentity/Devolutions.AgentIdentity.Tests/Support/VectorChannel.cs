using Devolutions.Agent.Channel.V1;

using Google.Protobuf;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The agent channel stream that <c>channel_proof</c> describes:
/// its <c>connect_case</c> opened at that case's <c>now</c>, with the vector challenge.
/// </summary>
internal static class VectorChannel
{
    private static ChannelProofVectors Vectors => TestVectors.Instance.ChannelProof;

    private static HttpSignatureCaseVector ConnectCase => TestVectors.Instance.HttpSignature.Case(Vectors.ConnectCase);

    /// <summary>
    /// The <c>now</c> of the opening request, at which the stream opens unless a test passes another clock.
    /// </summary>
    public static DateTimeOffset OpeningTime => ConnectCase.Now;

    /// <summary>
    /// Metadata that CONTRACT.agent-identity.md §3 accepts, with the keys that §3.1 says the agent always sends.
    /// </summary>
    public static IReadOnlyList<KeyValuePair<string, string>> ValidMetadata { get; } =
    [
        new("hostname", "device-a"),
        new("os_name", "Windows"),
        new("os_version", "10.0.26100"),
        new("arch", "x86_64"),
        new("agent_version", "2026.3.0"),
    ];

    /// <summary>
    /// Opens the stream through the public API.
    /// </summary>
    /// <param name="clock">The authority's clock, which reads <see cref="OpeningTime"/> when null.</param>
    /// <param name="status">
    /// The status to register the device's certificate with, instead of the status that the vector file gives it.
    /// </param>
    public static Task<ChannelOpening> OpenAsync(TimeProvider? clock = null, CertificateStatus? status = null)
    {
        return OpenAsync(new VectorAuthority(), clock, status);
    }

    /// <summary>
    /// Opens the stream through the public API, with the registry and the nonce store of <paramref name="authority"/>,
    /// which the test can then change before the handshake.
    /// </summary>
    public static Task<ChannelOpening> OpenAsync(
        VectorAuthority authority,
        TimeProvider? clock = null,
        CertificateStatus? status = null)
    {
        if (status is { } registeredStatus)
        {
            RegisterDevice(authority.Registry, registeredStatus, identityRevoked: false);
        }

        return OpenAsync(authority.Registry, authority.Nonces, clock);
    }

    /// <summary>
    /// Opens the stream through the public API, over <paramref name="registry"/>,
    /// which must answer for the device's certificate as the vector file registers it.
    /// </summary>
    public static async Task<ChannelOpening> OpenAsync(
        ICertificateRegistry registry,
        INonceStore? nonces = null,
        TimeProvider? clock = null)
    {
        RequestAuthenticator authenticator = new(
            registry,
            nonces ?? new RecordingNonceStore(),
            clock ?? new FixedTimeProvider(OpeningTime),
            new ScriptedRandomNumberGenerator(Vectors.Challenge));

        ChannelOpeningResult result = await VectorAuthority.OpenChannelAsync(authenticator, ConnectCase);

        // oracle: reference docs/agent-identity/test-vectors.json channel_proof.connect_case
        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Equal(Vectors.Challenge, result.Opening.Challenge.Challenge.Challenge_.ToByteArray());
        return result.Opening;
    }

    /// <summary>
    /// Registers the device's certificate again, as the vector file registers it but with this status and revocation.
    /// </summary>
    public static void RegisterDevice(FakeCertificateRegistry registry, CertificateStatus status, bool identityRevoked)
    {
        RegisteredCertificateVector device = TestVectors.Instance.HttpSignature.RegisteredCertificate(Vectors.Device);
        registry.Register(
            device.KeyId,
            new RegisteredCertificate(device.IdentityId, device.Certificate, status, identityRevoked));
    }

    /// <summary>
    /// A <c>Hello</c> that answers the Challenge of <paramref name="opening"/> with <paramref name="proof"/>
    /// and <see cref="ValidMetadata"/>.
    /// </summary>
    public static AgentMessage HelloMessage(ChannelOpening opening, byte[] proof)
    {
        AgentMessage message = new()
        {
            Id = Guid.NewGuid().ToString("D"),
            CorrelationId = opening.Challenge.Id,
            Hello = new Hello { Proof = ByteString.CopyFrom(proof) },
        };

        foreach ((string key, string value) in ValidMetadata)
        {
            message.Hello.Metadata.Add(key, value);
        }

        return message;
    }

    /// <summary>
    /// A <c>Hello</c> that the stream accepts:
    /// <see cref="HelloMessage"/> with the proof of the vector case <c>valid</c>.
    /// </summary>
    public static AgentMessage ValidHelloMessage(ChannelOpening opening)
    {
        return HelloMessage(opening, Vectors.Case("valid").Proof);
    }
}
