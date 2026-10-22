using System.Security.Cryptography;

using Devolutions.Agent.Channel.V1;
using Google.Protobuf;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The channel opening of CONTRACT.agent-identity.md §7.3 steps 1 and 2:
/// the verified opening request and the challenge that follows it.
/// </summary>
public class ChannelOpeningTests
{
    private const string UuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    private static ChannelProofVectors ChannelProof => TestVectors.Instance.ChannelProof;

    // CONTRACT.agent-identity.md §7.3 step 2: the first message is Challenge,
    // with 32 random bytes fresh for this stream.
    // CONTRACT.agent-identity.md §1 and §7.3: ids are lowercase hyphenated UUIDs.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public async Task ChallengeHolds32Bytes()
    {
        TestAuthority authority = new(TestAuthority.DefaultNow);

        ChannelOpening opening = await authority.OpenChannelAsync();

        ServerMessage challenge = opening.Challenge;
        Assert.Equal(ServerMessage.PayloadOneofCase.Challenge, challenge.PayloadCase);
        Assert.Equal(32, challenge.Challenge.Challenge_.Length);
        Assert.Matches(UuidPattern, challenge.Id);
    }

    // Step 2: the challenge holds 32 random bytes fresh for this stream.
    // A challenge reused across streams would let a proof captured on one stream authenticate another.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task EachOpeningHasItsOwnChallenge()
    {
        TestAuthority authority = new(TestAuthority.DefaultNow);

        ChannelOpening first = await authority.OpenChannelAsync();
        ChannelOpening second = await authority.OpenChannelAsync("EBESExQVFhcYGRobHB0eHw");

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        Assert.NotEqual(first.Challenge.Id, second.Challenge.Id);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        Assert.Equal(32, second.Challenge.Challenge.Challenge_.Length);
        Assert.NotEqual(
            first.Challenge.Challenge.Challenge_.ToByteArray(),
            second.Challenge.Challenge.Challenge_.ToByteArray());
    }

    // Steps 3 and 4: the proof covers the challenge as sent and the connect nonce,
    // and is verified with the key of the certificate that authenticated the opening,
    // so the opening keeps the nonce and that certificate for the handshake.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: reference docs/agent-identity/test-vectors.json channel_proof
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.registered.device-a
    [Fact]
    public async Task OpeningKeepsWhatTheChannelProofCovers()
    {
        VectorAuthority authority = new();
        HttpSignatureCaseVector connect = TestVectors.Instance.HttpSignature.Case(ChannelProof.ConnectCase);
        KeyVector device = TestVectors.Instance.Key(ChannelProof.Device);
        RegisteredCertificateVector registered =
            TestVectors.Instance.HttpSignature.RegisteredCertificate(ChannelProof.Device);
        authority.Clock.Now = connect.Now;

        ChannelOpeningResult result = await VectorAuthority.OpenChannelAsync(authority.Authenticator, connect);


        Assert.True(result.Succeeded);
        ChannelOpening opening = result.Opening;
        Assert.Equal(ChannelProof.ConnectNonce, opening.ConnectNonce);
        Assert.Equal(ChannelProof.PublicKeySec1, Sec1PublicKey(opening.Certificate.SubjectPublicKeyInfo));
        Assert.Equal(device.Thumbprint, opening.CertificateThumbprint);
        Assert.Equal(registered.IdentityId, opening.Certificate.IdentityId);
        Assert.Equal(registered.CertificateStatus, opening.Certificate.Status.ToString().ToLowerInvariant());
        Assert.Equal(registered.NotBefore, opening.Certificate.NotBefore);
        Assert.Equal(registered.NotAfter, opening.Certificate.NotAfter);
    }

    // Steps 3 and 4: the agent signs the challenge it received, and the server verifies that proof.
    // The handshake checks the proof against the challenge as sent,
    // so a host that edits the message object after sending it must not change what the agent has to sign.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task KeptChallengeDoesNotFollowEditsOfTheMessage()
    {
        TestAuthority authority = new(TestAuthority.DefaultNow);
        ChannelOpening opening = await authority.OpenChannelAsync();
        string sentId = opening.Challenge.Id;
        byte[] sentBytes = opening.Challenge.Challenge.Challenge_.ToByteArray();

        opening.Challenge.Id = Guid.NewGuid().ToString("D");
        opening.Challenge.Challenge.Challenge_ = ByteString.CopyFrom(new byte[32]);

        Assert.Equal(sentId, opening.ChallengeId);
        Assert.Equal(sentBytes, opening.ChallengeBytes.ToArray());
    }

    // A stream closes no later than its certificate's notAfter,
    // even while it waits for its Hello, so the opening gives the host that time.
    // The vector file states it in Unix seconds, independently of any time zone.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.registered.device-a
    [Fact]
    public async Task OpeningGivesTheNotAfterOfItsCertificate()
    {
        TestAuthority authority = new(TestAuthority.DefaultNow);

        ChannelOpening opening = await authority.OpenChannelAsync();

        Assert.Equal(
            TestVectors.Instance.HttpSignature.RegisteredCertificate("device-a").NotAfter,
            opening.CertificateNotAfter);
    }


    // SEC 1 §2.3.3: an uncompressed point is 0x04, then X and Y.
    private static byte[] Sec1PublicKey(byte[] subjectPublicKeyInfo)
    {
        using ECDsa key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        return [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];
    }
}
