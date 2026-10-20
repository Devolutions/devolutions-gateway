using Devolutions.Agent.Channel.V1;

using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

using Grpc.Core;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The channel handshake of CONTRACT.md §7.3 steps 3 and 4: the first agent message and the Welcome that answers it.
/// </summary>
public class ChannelHandshakeTests
{
    private const string UuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    // Messages that break exactly one rule of §7.3 step 4 that closes the stream with signature_invalid.
    private static readonly Dictionary<string, Func<ChannelOpening, AgentMessage>> SignatureFailures = new()
    {
        ["an Ack"] = opening => new AgentMessage
        {
            Id = NewId(),
            CorrelationId = opening.Challenge.Id,
            Ack = new Ack(),
        },
        ["a message without payload"] = opening => new AgentMessage
        {
            Id = NewId(),
            CorrelationId = opening.Challenge.Id,
        },
        ["a Hello without correlation_id"] = opening =>
            Altered(VectorChannel.ValidHelloMessage(opening), message => message.ClearCorrelationId()),
        ["a Hello correlated to another id"] = opening =>
            Altered(VectorChannel.ValidHelloMessage(opening), message => message.CorrelationId = NewId()),

        // The Hello must carry the Challenge id as sent, so the same UUID in uppercase is another id.
        ["a Hello correlated to the Challenge id in uppercase"] = opening => Altered(
            VectorChannel.ValidHelloMessage(opening),
            message => message.CorrelationId = opening.Challenge.Id.ToUpperInvariant()),

        // The shared vectors cover the other ways a proof fails, one of which is repeated here to pair it below.
        ["a Hello with the proof of another device"] = opening => VectorChannel.HelloMessage(opening, OtherKeyProof),
        ["a Hello with a 63-byte proof"] = opening => VectorChannel.HelloMessage(opening, ValidProof[..63]),
        ["a Hello with a valid proof and one more byte"] = opening =>
            VectorChannel.HelloMessage(opening, [.. ValidProof, 0x00]),
    };

    // Alterations that break a rule which §7.3 step 4 checks after the one a message of SignatureFailures breaks.
    private static readonly Dictionary<string, Action<AgentMessage>> LaterFailures = new()
    {
        ["no correlation_id"] = message => message.ClearCorrelationId(),
        ["a proof by another device"] = message => message.Hello.Proof = ByteString.CopyFrom(OtherKeyProof),
        ["invalid metadata"] = message => message.Hello.Metadata.Add("Hostname", "device-a"),
    };

    // Calls that end the handshake of an opening, one per outcome.
    private static readonly Dictionary<string, Func<ChannelOpening, ChannelHandshakeResult>> HandshakeEnds = new()
    {
        ["a valid Hello"] = opening => opening.VerifyHello(VectorChannel.ValidHelloMessage(opening)),
        ["a Hello with the proof of another device"] = opening =>
            opening.VerifyHello(VectorChannel.HelloMessage(opening, OtherKeyProof)),
        ["a Hello with invalid metadata"] = opening =>
            opening.VerifyHello(Altered(VectorChannel.ValidHelloMessage(opening), LaterFailures["invalid metadata"])),
        ["no Hello in time"] = opening => opening.HelloTimedOut(),
    };

    public static TheoryData<string> SignatureFailureNames => new(SignatureFailures.Keys);

    // Every way to end a handshake, followed by each of the two calls a host makes.
    public static TheoryData<string, string> HandshakeEndsThenAnotherCall
    {
        get
        {
            TheoryData<string, string> cases = new();

            foreach (string first in HandshakeEnds.Keys)
            {
                cases.Add(first, "a valid Hello");
                cases.Add(first, "no Hello in time");
            }

            return cases;
        }
    }

    public static TheoryData<string, string> FailurePairs => new()
    {
        { "an Ack", "no correlation_id" },
        { "a message without payload", "no correlation_id" },
        { "a Hello without correlation_id", "a proof by another device" },
        { "a Hello correlated to another id", "a proof by another device" },
        { "a Hello without correlation_id", "invalid metadata" },
        { "a Hello correlated to another id", "invalid metadata" },
        { "a Hello with the proof of another device", "invalid metadata" },
        { "a Hello with a 63-byte proof", "invalid metadata" },
    };

    private static byte[] ValidProof => TestVectors.Instance.ChannelProof.Case("valid").Proof;

    // A raw 64-byte signature over the right bytes, by the key of device-b.
    private static byte[] OtherKeyProof => TestVectors.Instance.ChannelProof.Case("wrong_key").Proof;

    // CONTRACT.md §7.3 step 4 and §7.4: UNAUTHENTICATED with error-code signature_invalid.
    [Theory]
    [MemberData(nameof(SignatureFailureNames))]
    public async Task FirstMessageFailingTheProofRulesIsSignatureInvalid(string failure)
    {
        ChannelHandshakeResult result = await VerifyAsync(SignatureFailures[failure]);

        AssertFailed(result, AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated);
    }

    // CONTRACT.md §7.3 step 4: a Hello that proves the key but carries metadata violating §3 is
    // INVALID_ARGUMENT with error-code invalid_request.
    [Fact]
    public async Task HelloWithInvalidMetadataIsInvalidRequest()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        LaterFailures["invalid metadata"](hello);

        ChannelHandshakeResult result = opening.VerifyHello(hello);

        AssertFailed(result, AgentIdentityErrorCode.InvalidRequest, StatusCode.InvalidArgument);
    }

    // CONTRACT.md §7.3 step 4 checks the payload, the correlation_id, the proof, then the metadata,
    // and a message breaking two rules fails as it would for the earlier rule alone.
    // An agent that has not proved the key never learns whether its metadata would pass.
    [Theory]
    [MemberData(nameof(FailurePairs))]
    public async Task EarlierFailureWins(string earlier, string later)
    {
        ChannelHandshakeResult earlierAlone = await VerifyAsync(SignatureFailures[earlier]);
        ChannelHandshakeResult laterAlone =
            await VerifyAsync(opening => Altered(VectorChannel.ValidHelloMessage(opening), LaterFailures[later]));

        ChannelHandshakeResult result =
            await VerifyAsync(opening => Altered(SignatureFailures[earlier](opening), LaterFailures[later]));

        Assert.NotEqual(laterAlone.FailureDetail, earlierAlone.FailureDetail);
        AssertFailed(result, AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated);
        Assert.Equal(earlierAlone.FailureDetail, result.FailureDetail);
    }

    // CONTRACT.md §7.3 step 4: the server verifies the proof with the key of the certificate that authenticated the
    // opening request, so the stream is authenticated for that certificate and its identity.
    // The vector file states the facts of the certificate, in Unix seconds, independently of any time zone.
    [Fact]
    public async Task ValidHelloAuthenticatesTheIdentityOfTheOpeningCertificate()
    {
        RegisteredCertificateVector registered =
            TestVectors.Instance.HttpSignature.RegisteredCertificate(TestVectors.Instance.ChannelProof.Device);
        ChannelOpening opening = await VectorChannel.OpenAsync();

        ChannelHandshakeResult result = opening.VerifyHello(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        AuthenticatedIdentity identity = result.Identity;
        Assert.Equal(registered.IdentityId, identity.IdentityId);
        Assert.Equal(registered.KeyId, identity.CertificateThumbprint);
        Assert.Equal(registered.CertificateStatus, identity.CertificateStatus.ToString().ToLowerInvariant());
        Assert.Equal(registered.NotBefore, identity.CertificateNotBefore);
        Assert.Equal(registered.NotAfter, identity.CertificateNotAfter);
        Assert.Equal(AgentOperation.Connect, identity.Operation);
        Assert.Null(result.Error);
        Assert.Null(result.FailureDetail);
    }

    // CONTRACT.md §6 table: a channel opening accepts a pending certificate as well as a current one,
    // and the identity reports which of the two opened the stream.
    [Fact]
    public async Task IdentityHasTheStatusOfTheOpeningCertificate()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync(status: CertificateStatus.Pending);

        ChannelHandshakeResult result = opening.VerifyHello(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Equal(CertificateStatus.Pending, result.Identity.CertificateStatus);
    }

    // CONTRACT.md §3: the server replaces the identity's metadata with the metadata of each authenticated Hello.
    [Fact]
    public async Task ValidHelloYieldsItsMetadata()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();

        ChannelHandshakeResult result = opening.VerifyHello(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Equal(VectorChannel.ValidMetadata, result.Metadata);
    }

    // CONTRACT.md §3: metadata may be an empty object.
    // A protobuf map without entries is also how a Hello without metadata arrives,
    // so the rule that rejects a JSON body without metadata cannot apply here.
    [Fact]
    public async Task HelloWithoutMetadataSucceeds()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        hello.Hello.Metadata.Clear();

        ChannelHandshakeResult result = opening.VerifyHello(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Empty(result.Metadata);
    }

    // CONTRACT.md §7.3 step 4: Welcome has correlation_id = Hello id.
    // CONTRACT.md §1 and §7.3: envelope ids are lowercase hyphenated UUIDs.
    // The Hello id is in uppercase, so a Welcome that normalized it would no longer match what the agent sent.
    [Fact]
    public async Task WelcomeAnswersTheHello()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        hello.Id = NewId().ToUpperInvariant();

        ChannelHandshakeResult result = opening.VerifyHello(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
        ServerMessage welcome = result.Welcome;
        Assert.Equal(ServerMessage.PayloadOneofCase.Welcome, welcome.PayloadCase);
        Assert.Matches(UuidPattern, welcome.Id);
        Assert.NotEqual(opening.Challenge.Id, welcome.Id);
        Assert.True(welcome.HasCorrelationId);
        Assert.Equal(hello.Id, welcome.CorrelationId);
    }

    // The clock returns the time of the opening, then the time of the handshake, then a later time.
    // The Welcome carries the time at which the server answers, from that one reading.
    [Fact]
    public async Task WelcomeCarriesTheServerTimeOfTheHandshake()
    {
        DateTimeOffset opened = VectorChannel.OpeningTime;
        DateTimeOffset answered = opened.AddMilliseconds(3_250);
        ChannelOpening opening = await VectorChannel.OpenAsync(
            new SteppingTimeProvider(opened, answered, answered.AddDays(1).AddMilliseconds(500)));

        ChannelHandshakeResult result = opening.VerifyHello(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        Timestamp serverTime = result.Welcome.Welcome.ServerTime;
        Assert.Equal(answered.ToUnixTimeSeconds(), serverTime.Seconds);
        Assert.Equal(250_000_000, serverTime.Nanos);
    }

    // The agent answers the Challenge it received, so the handshake holds the Hello to the id and bytes as sent,
    // even if the host later edits the message object it sent.
    [Fact]
    public async Task HandshakeChecksTheChallengeAsSent()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        opening.Challenge.Id = NewId();
        opening.Challenge.Challenge.Challenge_ = ByteString.CopyFrom(new byte[32]);

        ChannelHandshakeResult result = opening.VerifyHello(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
    }

    // CONTRACT.md §7.3 step 4: no Hello within 10 s closes the stream with signature_invalid.
    [Fact]
    public async Task NoHelloInTimeIsSignatureInvalid()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();

        ChannelHandshakeResult result = opening.HelloTimedOut();

        AssertFailed(result, AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated);
    }

    // CONTRACT.md §7.3 step 4: the server waits 10 s for the Hello.
    [Fact]
    public void HelloTimeoutIs10Seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(10), ChannelHandshake.HelloTimeout);
    }

    // The first agent message decides the stream: a second one could retry a failed proof,
    // and a late Hello could authenticate a stream that already timed out.
    [Theory]
    [MemberData(nameof(HandshakeEndsThenAnotherCall))]
    public async Task HandshakeEndsAtTheFirstCall(string first, string second)
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        HandshakeEnds[first](opening);

        Assert.Throws<InvalidOperationException>(() => HandshakeEnds[second](opening));
    }

    // CONTRACT.md §7.3 step 4 and §7.4: the server closes the stream with the gRPC status of the failure
    // and the trailers `error-code: <§5.4 code>` and `server-time: <RFC 3339>`, which the agent reads.
    [Theory]
    [InlineData("a Hello with the proof of another device", StatusCode.Unauthenticated, "signature_invalid")]
    [InlineData("a Hello with invalid metadata", StatusCode.InvalidArgument, "invalid_request")]
    [InlineData("no Hello in time", StatusCode.Unauthenticated, "signature_invalid")]
    public async Task FailureClosesTheStreamWithTheContractStatusAndTrailers(
        string end,
        StatusCode expectedStatus,
        string expectedCode)
    {
        DateTimeOffset serverTime = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
        ChannelOpening opening = await VectorChannel.OpenAsync();
        ChannelHandshakeResult result = HandshakeEnds[end](opening);
        Assert.False(result.Succeeded);

        RpcException exception = result.Error.ToRpcException(serverTime);

        Assert.Equal(expectedStatus, exception.StatusCode);
        Assert.Equal(
            [("error-code", expectedCode), ("server-time", "2026-09-24T12:00:00Z")],
            exception.Trailers.Select(entry => (entry.Key, entry.Value)));
    }

    private static void AssertFailed(
        ChannelHandshakeResult result,
        AgentIdentityErrorCode expectedCode,
        StatusCode expectedStatus)
    {
        Assert.False(result.Succeeded);
        Assert.Equal(expectedCode, result.Error.Code);
        Assert.Equal(expectedStatus, result.Error.ToRpcException(DateTimeOffset.UnixEpoch).StatusCode);
        Assert.False(string.IsNullOrEmpty(result.FailureDetail));
        Assert.Null(result.Identity);
        Assert.Null(result.Metadata);
        Assert.Null(result.Welcome);
    }

    private static AgentMessage Altered(AgentMessage message, Action<AgentMessage> alteration)
    {
        alteration(message);
        return message;
    }

    // Opens the vector stream and verifies the first message built for it.
    private static async Task<ChannelHandshakeResult> VerifyAsync(Func<ChannelOpening, AgentMessage> firstMessage)
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        return opening.VerifyHello(firstMessage(opening));
    }

    private static string NewId()
    {
        return Guid.NewGuid().ToString("D");
    }
}
