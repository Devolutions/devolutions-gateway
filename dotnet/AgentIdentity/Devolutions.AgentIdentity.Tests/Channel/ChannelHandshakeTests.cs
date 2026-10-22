using Devolutions.Agent.Channel.V1;

using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

using Grpc.Core;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The channel handshake of CONTRACT.agent-identity.md §7.3 steps 3 and 4:
/// the first agent message and the Welcome that answers it.
/// </summary>
public class ChannelHandshakeTests
{
    private const string UuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    // Text that the metadata entry where a Hello fails holds in its key and in its value.
    private const string LeakedKey = "leaked_key";
    private const string LeakedValue = "leaked value";

    // Metadata entries that CONTRACT.agent-identity.md §3 rejects, by name,
    // each with a key holding LeakedKey and a value holding LeakedValue.
    private static readonly Dictionary<string, KeyValuePair<string, string>> InvalidMetadataEntries = new()
    {
        ["a key outside the pattern"] = new($"{LeakedKey}\n", LeakedValue),
        ["a value with a control character"] = new(LeakedKey, $"{LeakedValue}\u0007"),
        ["a value of 1025 UTF-8 bytes"] = new(LeakedKey, LeakedValue + new string('a', 1025 - LeakedValue.Length)),
    };

    // Messages that break exactly one rule of §7.3 step 4 that closes the stream with signature_invalid.
    // CONTRACT.agent-identity.md §7.3 step 4 and §7.4: UNAUTHENTICATED with error-code signature_invalid.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
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

    // Alterations that break a rule which §7.3 step 4 checks after the one a message of SignatureFailures breaks,
    // by the name of the message failure that each makes of a valid Hello.
    private static readonly Dictionary<string, Action<AgentMessage>> LaterFailures = new()
    {
        ["a Hello without correlation_id"] = message => message.ClearCorrelationId(),
        ["a Hello with the proof of another device"] =
            message => message.Hello.Proof = ByteString.CopyFrom(OtherKeyProof),
        ["a Hello with invalid metadata"] = message => message.Hello.Metadata.Add("Hostname", "device-a"),
    };

    // Messages that break two rules of §7.3 step 4, by the name of the earlier failure and of the later one.
    private static readonly (string Earlier, string Later)[] MessageFailurePairs =
    [
        ("an Ack", "a Hello without correlation_id"),
        ("a message without payload", "a Hello without correlation_id"),
        ("a Hello without correlation_id", "a Hello with the proof of another device"),
        ("a Hello correlated to another id", "a Hello with the proof of another device"),
        ("a Hello without correlation_id", "a Hello with invalid metadata"),
        ("a Hello correlated to another id", "a Hello with invalid metadata"),
        ("a Hello with the proof of another device", "a Hello with invalid metadata"),
        ("a Hello with a 63-byte proof", "a Hello with invalid metadata"),
    ];

    // Answers that the registry must never give for the thumbprint of the certificate that opened the stream.
    private static readonly Dictionary<string, Func<RegisteredCertificate>> WrongRegistryAnswers = new()
    {
        ["another certificate"] = () =>
            new RegisteredCertificate(DeviceA.IdentityId, DeviceB.Certificate, CertificateStatus.Current, false),
        ["the certificate for another identity"] = () =>
            new RegisteredCertificate(DeviceB.IdentityId, DeviceA.Certificate, CertificateStatus.Current, false),
    };

    // Calls that end the handshake of an opening, one per outcome.
    private static readonly Dictionary<string, Func<ChannelOpening, ValueTask<ChannelHandshakeResult>>> HandshakeEnds =
        new()
        {
            ["a valid Hello"] = opening => opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening)),
            ["a Hello with the proof of another device"] = opening =>
                opening.VerifyHelloAsync(VectorChannel.HelloMessage(opening, OtherKeyProof)),
            ["a Hello with invalid metadata"] = opening => opening.VerifyHelloAsync(
                Altered(VectorChannel.ValidHelloMessage(opening), LaterFailures["a Hello with invalid metadata"])),
            ["no Hello in time"] = opening => opening.HelloTimedOutAsync(),
            ["the first message could not be decoded"] = opening => opening.FirstMessageUnreadableAsync(),
        };

    // The calls that end the handshake of a stream that OpenBeforeNotAfterAsync opens.
    private static readonly Dictionary<string, Func<ChannelOpening, AgentMessage, ValueTask<ChannelHandshakeResult>>>
        HandshakeEndsBeforeNotAfter = new()
        {
            ["a valid Hello"] = (opening, hello) => opening.VerifyHelloAsync(hello),
            ["no Hello in time"] = (opening, _) => opening.HelloTimedOutAsync(),
            ["the first message could not be decoded"] = (opening, _) => opening.FirstMessageUnreadableAsync(),
        };

    public static TheoryData<string> FailureNames => new(Failures.Keys);

    public static TheoryData<string> InvalidMetadataEntryNames => new(InvalidMetadataEntries.Keys);

    public static TheoryData<string> ScenarioNames => new(Scenarios.Keys);

    // Each wrong answer of the registry, to each of the calls that read it.
    public static TheoryData<string, string> WrongRegistryAnswersAndCalls
    {
        get
        {
            TheoryData<string, string> cases = new();

            foreach (string answer in WrongRegistryAnswers.Keys)
            {
                cases.Add(answer, "a valid Hello");
                cases.Add(answer, "no Hello in time");
                cases.Add(answer, "the first message could not be decoded");
            }

            return cases;
        }
    }

    // Each pair of failures that the handshake checks one after the other.
    public static TheoryData<string, string> FailurePairNames
    {
        get
        {
            TheoryData<string, string> cases = new();

            foreach ((string earlier, string later) in FailurePairs.Keys)
            {
                cases.Add(earlier, later);
            }

            return cases;
        }
    }

    // Every way to end a handshake.
    public static TheoryData<string> HandshakeEndNames => new(HandshakeEnds.Keys);

    private static byte[] ValidProof => TestVectors.Instance.ChannelProof.Case("valid").Proof;

    // CONTRACT.agent-identity.md §7.4: the closures that apply to a stream even while it awaits its Hello,
    // in the order the handshake checks them, with the code and the gRPC status that close the stream.
    // The certificate of device-a expires 70 days after the vector opening, so a reading after its notAfter is also
    // after the Hello timeout.
    private static OrderedDictionary<string, Failure> Closures => new()
    {
        // Step 4: a certificate that is no longer registered, or whose identity was deleted, is identity_unknown.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        ["the certificate is no longer registered"] = new(
            new Scenario { CertificateRemoved = true },
            AgentIdentityErrorCode.IdentityUnknown,
            StatusCode.Unauthenticated),
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        ["the identity is revoked"] = new(
            new Scenario { IdentityRevoked = true },
            AgentIdentityErrorCode.IdentityRevoked,
            StatusCode.PermissionDenied),
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        ["the certificate has expired"] = new(
            new Scenario { HandshakeTime = DeviceANotAfter.AddTicks(1) },
            AgentIdentityErrorCode.CertificateExpired,
            StatusCode.Unauthenticated),
    };

    // The failures that the handshake decides from the registry and the clock before it reads the message:
    // the closures, then a late Hello.
    private static OrderedDictionary<string, Failure> EarlyFailures => new(Closures)
    {
        // Step 4: no Hello within 10 s closes the stream with signature_invalid.
        // A Hello that the host passes on after the timeout fails, so a late host timer cannot let it through.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        ["the Hello is late"] = new(
            new Scenario { HandshakeTime = VectorChannel.OpeningTime.AddSeconds(10).AddTicks(1) },
            AgentIdentityErrorCode.SignatureInvalid,
            StatusCode.Unauthenticated),
    };

    // CONTRACT.agent-identity.md §7.3 step 4: every message that breaks one of its rules,
    // each of SignatureFailures with signature_invalid, and invalid metadata in a valid Hello with invalid_request.
    private static Dictionary<string, Failure> MessageFailures =>
        SignatureFailures
            .Select(failure => KeyValuePair.Create(
                failure.Key,
                new Failure(
                    new Scenario { FirstMessage = failure.Value },
                    AgentIdentityErrorCode.SignatureInvalid,
                    StatusCode.Unauthenticated)))

            // A Hello that proves the key but carries metadata violating §3 is INVALID_ARGUMENT with error-code
            // invalid_request.
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
            .Append(KeyValuePair.Create(
                "a Hello with invalid metadata",
                new Failure(
                    new Scenario
                    {
                        FirstMessage = opening => Altered(
                            VectorChannel.ValidHelloMessage(opening),
                            LaterFailures["a Hello with invalid metadata"]),
                    },
                    AgentIdentityErrorCode.InvalidRequest,
                    StatusCode.InvalidArgument)))
            .ToDictionary();

    // The ways a handshake ends with no Hello to verify, by name.
    private static Dictionary<string, Scenario> NoHelloEnds => new()
    {
        // No first message arrives, and the host ends the handshake for the timeout.
        ["no Hello in time"] = new() { FirstMessage = null },

        // Step 4: a first message that cannot be decoded is not a Hello, since no proof can be read from it.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        ["the first message could not be decoded"] = new() { FirstMessageUnreadable = true },
    };

    // Every failure by name: each early failure, each message failure,
    // and each end with no Hello, alone with signature_invalid (§7.3 step 4) and after each closure,
    // which §7.4 applies first.
    // CONTRACT.agent-identity.md §7.3 step 4: no Hello within 10 s closes the stream with signature_invalid,
    // and so does a first message that cannot be decoded, which is not a Hello.
    // CONTRACT.agent-identity.md §7.4: revocation and expiry close a stream still awaiting its Hello ahead of the
    // failures of §7.3 step 4, the timeout included, and so does a deletion, which leaves the certificate unregistered.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    private static Dictionary<string, Failure> Failures =>
        EarlyFailures
            .Concat(MessageFailures)
            .Concat(NoHelloEnds.SelectMany(end => Closures
                .Select(closure => KeyValuePair.Create(
                    WithClosure(end.Key, closure.Key),
                    closure.Value with { Scenario = closure.Value.Scenario.And(end.Value) }))
                .Prepend(KeyValuePair.Create(
                    end.Key,
                    new Failure(end.Value, AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated)))))
            .ToDictionary();

    // Every scenario by name: a valid handshake and each failure.
    private static Dictionary<string, Scenario> Scenarios =>
        Failures
            .Select(failure => KeyValuePair.Create(failure.Key, failure.Value.Scenario))
            .Prepend(KeyValuePair.Create("a valid Hello", new Scenario()))
            .ToDictionary();

    // Each pair of failures that the handshake checks one after the other, by name, with the scenario failing both:
    // a message breaking two rules of §7.3 step 4, a failure decided before the message with each failure checked
    // after it, and for each end with no Hello, a closure with each closure checked after it and with that end alone.
    private static Dictionary<(string Earlier, string Later), Scenario> FailurePairs
    {
        get
        {
            Dictionary<(string Earlier, string Later), Scenario> pairs = MessageFailurePairs.ToDictionary(
                pair => pair,
                pair => new Scenario
                {
                    FirstMessage = opening =>
                        Altered(SignatureFailures[pair.Earlier](opening), LaterFailures[pair.Later]),
                });

            AddOrderedPairs(pairs, [.. EarlyFailures.Keys], MessageFailures.Keys);

            foreach (string end in NoHelloEnds.Keys)
            {
                AddOrderedPairs(pairs, [.. Closures.Keys.Select(closure => WithClosure(end, closure))], [end]);
            }

            return pairs;
        }
    }

    // A raw 64-byte signature over the right bytes, by the key of device-b.
    private static byte[] OtherKeyProof => TestVectors.Instance.ChannelProof.Case("wrong_key").Proof;

    private static KeyVector DeviceA => TestVectors.Instance.Key("device-a");

    private static KeyVector DeviceB => TestVectors.Instance.Key("device-b");

    // The notAfter of the certificate of device-a, which opens every stream of these tests,
    // as the vector file states it in Unix seconds, independently of any time zone.
    private static DateTimeOffset DeviceANotAfter =>
        TestVectors.Instance.HttpSignature.RegisteredCertificate("device-a").NotAfter;

    // Each failure, alone, closes the stream with its code and gRPC status;
    // the markers where each failure is defined name the rule that decides its code.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [MemberData(nameof(FailureNames))]
    public async Task FailureClosesTheStreamWithItsCode(string failure)
    {
        (Scenario scenario, AgentIdentityErrorCode expectedCode, StatusCode expectedStatus) = Failures[failure];

        ChannelHandshakeResult result = await HandshakeAsync(scenario);

        AssertFailed(result, expectedCode, expectedStatus);
    }

    // The failure detail goes to host logs, so it holds no key or value of the metadata, valid or not,
    // since an agent could otherwise write into the authority's logs.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Failure details
    [Theory]
    [MemberData(nameof(InvalidMetadataEntryNames))]
    public async Task FailureDetailHoldsNoMetadataKeyOrValue(string entry)
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        (string key, string value) = InvalidMetadataEntries[entry];
        hello.Hello.Metadata.Add(key, value);

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(hello);

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        AssertFailed(result, AgentIdentityErrorCode.InvalidRequest, StatusCode.InvalidArgument);
        Assert.DoesNotContain(LeakedKey, result.FailureDetail);
        Assert.DoesNotContain(LeakedValue, result.FailureDetail);
    }

    // The handshake checks its failures in an order, and a stream that fails two of them closes as it would for the
    // earlier one alone.
    // CONTRACT.agent-identity.md §6 step 4 and §7.4: the registry and the clock decide before the message,
    // in this order:
    // a certificate no longer registered, a revoked identity, an expired certificate, then a late Hello.
    // A stream that fails one of them is closed for that reason, whatever the message holds, and so is a stream
    // without Hello, which gets identity_unknown for an identity revoked and then deleted.
    // A revocation or a deletion found when the Hello arrives or the wait times out wins over a certificate also past
    // its notAfter, whether a Hello arrived, none arrived in time, or the first message could not be decoded.
    // The late Hello is signature_invalid like the message failures, and comes before all of them, metadata included.
    // CONTRACT.agent-identity.md §7.3 step 4 then checks the payload, the correlation_id, the proof, then the metadata,
    // so an agent that has not proved the key never learns whether its metadata would pass.
    // Two failures that both close the stream with signature_invalid close it with signature_invalid together.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Theory]
    [MemberData(nameof(FailurePairNames))]
    public async Task EarlierFailureWins(string earlier, string later)
    {
        (_, AgentIdentityErrorCode expectedCode, StatusCode expectedStatus) = Failures[earlier];

        ChannelHandshakeResult result = await HandshakeAsync(FailurePairs[(earlier, later)]);

        AssertFailed(result, expectedCode, expectedStatus);
    }

    // The shared intent, security invariant 5: revocation blocks authentication, including of a stream whose identity
    // the host cannot know yet.
    // CONTRACT.agent-identity.md §7.4: PERMISSION_DENIED
    // with the trailers `error-code: identity_revoked` and `server-time`, in no stated order.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Fact]
    public async Task IdentityRevokedDuringTheHandshakeIsIdentityRevoked()
    {
        DateTimeOffset serverTime = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

        ChannelHandshakeResult result = await HandshakeAsync(new Scenario { IdentityRevoked = true });

        AgentIdentityError error =
            AssertFailed(result, AgentIdentityErrorCode.IdentityRevoked, StatusCode.PermissionDenied);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        Assert.Equal(
            [("error-code", "identity_revoked"), ("server-time", "2026-09-24T12:00:00Z")],
            error.ToRpcException(serverTime).Trailers
                .Select(entry => (entry.Key, entry.Value))
                .OrderBy(entry => entry.Key, StringComparer.Ordinal));
    }

    // The identity reports the status that the registry holds for the opening certificate when the handshake ends.
    // CONTRACT.agent-identity.md §6 table: a channel opening accepts a pending certificate as well as a current one.
    // CONTRACT.agent-identity.md §5.5: a confirm during the handshake makes a pending certificate current.
    // CONTRACT.agent-identity.md §7.4: a stream whose certificate is retired while it awaits its Hello still completes
    // the handshake, then gets the treatment of every stream of a retired certificate,
    // so the result reports the retirement.
    // Failing it would send a healthy agent the terminal identity_unknown.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    [InlineData(CertificateStatus.Pending, CertificateStatus.Pending)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §confirm
    [InlineData(CertificateStatus.Pending, CertificateStatus.Current)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData(CertificateStatus.Current, CertificateStatus.Retired)]
    public async Task IdentityHasTheCertificateStatusAtTheEndOfTheHandshake(
        CertificateStatus opened,
        CertificateStatus atHandshake)
    {
        VectorAuthority authority = new();
        ChannelOpening opening = await VectorChannel.OpenAsync(authority, status: opened);
        VectorChannel.RegisterDevice(authority.Registry, atHandshake, identityRevoked: false);

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Equal(atHandshake, result.Identity.CertificateStatus);
    }

    // A retired certificate passes the handshake, but the revocation of its identity still blocks it.
    // CONTRACT.agent-identity.md §7.4: revocation closes a stream still awaiting its Hello, with PERMISSION_DENIED and
    // identity_revoked.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Fact]
    public async Task RevocationWinsOverARetiredCertificate()
    {
        ChannelHandshakeResult result = await HandshakeAsync(
            new Scenario { Status = CertificateStatus.Retired, IdentityRevoked = true });

        AssertFailed(result, AgentIdentityErrorCode.IdentityRevoked, StatusCode.PermissionDenied);
    }

    // CONTRACT.agent-identity.md §7.4 applies a deletion or a revocation since the opening to a stream awaiting its
    // Hello, so whatever the outcome, the handshake reads the registry again
    // for the certificate that opened the stream.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task HandshakeReadsTheRegistryForTheOpeningCertificate(string scenario)
    {
        VectorAuthority openingOnly = new();
        await VectorChannel.OpenAsync(openingOnly);
        VectorAuthority authority = new();

        await HandshakeAsync(Scenarios[scenario], authority);

        // The lookups of the opening, then those of the handshake.
        string[] handshakeLookups = [.. authority.Registry.Lookups.Skip(openingOnly.Registry.Lookups.Count)];
        Assert.NotEmpty(handshakeLookups);
        Assert.All(handshakeLookups, thumbprint => Assert.Equal(DeviceA.Thumbprint, thumbprint));
    }

    // CONTRACT.agent-identity.md §7.4: revocation closes live streams, and a stream awaiting its Hello is checked for
    // revocation and deletion when the Hello arrives or the wait times out.
    // The host adds the stream to the live streams that its revocation and deletion paths close before it ends the
    // handshake, so a revocation that commits before the handshake's registry read fails the handshake,
    // and one that commits after that read finds the stream.
    // No revocation slips between the two only if that read happens within the call, after the host added the stream,
    // rather than at the opening.
    // The library cannot check that the host adds the stream, so the test pins only the library's side of the order.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Theory]
    [InlineData("a valid Hello")]
    [InlineData("no Hello in time")]
    [InlineData("the first message could not be decoded")]
    public async Task HandshakeReadsTheRegistryAfterTheHostAddsTheStream(string end)
    {
        LiveStreamRecordingRegistry registry = new();
        ChannelOpening opening = await OpenAsync(registry);
        registry.StreamAdded = true;

        await HandshakeEnds[end](opening);

        Assert.Contains(true, registry.StreamAddedAtLookups);
    }

    // The registry answers a thumbprint with the certificate issued under it, for its one identity,
    // so another answer is a host bug, which must fail as a server error rather than draw an outcome the agent acts on.
    // CONTRACT.agent-identity.md §5.4: an unexpected server failure is the transient `500 unavailable`,
    // whereas identity_unknown and identity_revoked are terminal; the exception type is the library's API.
    // oracle: mutant a handshake that acts on a registry answer for another certificate,
    // or for the opening certificate under another identity
    [Theory]
    [MemberData(nameof(WrongRegistryAnswersAndCalls))]
    public async Task RegistryAnsweringForAnotherCertificateOrIdentityThrows(string answer, string call)
    {
        VectorAuthority authority = new();
        ChannelOpening opening = await VectorChannel.OpenAsync(authority);
        authority.Registry.Register(opening.CertificateThumbprint, WrongRegistryAnswers[answer]());

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await HandshakeEnds[call](opening));
    }

    // CONTRACT.agent-identity.md §7.3 step 4 decides a stream by its first agent message or by the timeout, not both.
    // A Hello timer that fires while the registry answers the Hello comes after the Hello,
    // so it does not fail the Hello.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Fact]
    public async Task HelloDecidesTheStreamWhenTheTimeoutFiresDuringItsLookup()
    {
        VectorAuthority authority = new();
        ChannelOpening opening = await VectorChannel.OpenAsync(authority);
        TaskCompletionSource answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        authority.Registry.Gate = answer.Task;
        ValueTask<ChannelHandshakeResult> verifying =
            opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));
        Assert.False(verifying.IsCompleted);

        _ = opening.HelloTimedOutAsync();
        answer.SetResult();

        Assert.True((await verifying).Succeeded);
    }

    // CONTRACT.agent-identity.md §7.3 step 4 decides a stream by its first agent message or by the timeout, not both,
    // and closes it for the timeout with signature_invalid.
    // A Hello that arrives while the registry answers the timeout comes after it,
    // so it cannot authenticate a stream that is being closed.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Fact]
    public async Task TimeoutDecidesTheStreamWhenAHelloArrivesDuringItsLookup()
    {
        VectorAuthority authority = new();
        ChannelOpening opening = await VectorChannel.OpenAsync(authority);
        TaskCompletionSource answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        authority.Registry.Gate = answer.Task;
        ValueTask<ChannelHandshakeResult> timingOut = opening.HelloTimedOutAsync();
        Assert.False(timingOut.IsCompleted);

        ValueTask<ChannelHandshakeResult> verifying =
            opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));
        answer.SetResult();

        await AssertYieldsNoIdentityAsync(() => verifying);
        AssertFailed(await timingOut, AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated);
    }

    // CONTRACT.agent-identity.md §6 reads the clock before the registry, and so does the handshake,
    // so a Hello that arrives in time stays in time however long the registry takes to answer.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task SlowRegistryDoesNotMakeAHelloLate()
    {
        VectorAuthority authority = new();
        FixedTimeProvider clock = new(VectorChannel.OpeningTime);
        ChannelOpening opening = await VectorChannel.OpenAsync(authority, clock);
        TaskCompletionSource answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        authority.Registry.Gate = answer.Task;
        clock.Now = VectorChannel.OpeningTime.AddSeconds(10);
        ValueTask<ChannelHandshakeResult> verifying =
            opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        clock.Now = clock.Now.AddTicks(1);
        answer.SetResult();
        ChannelHandshakeResult result = await verifying;

        Assert.True(result.Succeeded, result.FailureDetail);
    }

    // Step 4: the server verifies the proof with the key of the certificate that authenticated the opening request,
    // so the stream is authenticated for that certificate and its identity.
    // The vector file states the facts of the certificate, in Unix seconds, independently of any time zone.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.registered.device-a
    [Fact]
    public async Task ValidHelloAuthenticatesTheIdentityOfTheOpeningCertificate()
    {
        RegisteredCertificateVector registered =
            TestVectors.Instance.HttpSignature.RegisteredCertificate(TestVectors.Instance.ChannelProof.Device);
        ChannelOpening opening = await VectorChannel.OpenAsync();

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        AuthenticatedIdentity identity = result.Identity;
        Assert.Equal(registered.IdentityId, identity.IdentityId);
        Assert.Equal(registered.KeyId, identity.CertificateThumbprint);
        Assert.Equal(registered.CertificateStatus, identity.CertificateStatus.ToString().ToLowerInvariant());
        Assert.Equal(registered.NotBefore, identity.CertificateNotBefore);
        Assert.Equal(registered.NotAfter, identity.CertificateNotAfter);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
        Assert.Equal(AgentOperation.Connect, identity.Operation);
    }

    // The server replaces the identity's metadata with the metadata of each authenticated Hello.
    // Metadata is an object of string to string, whose entries have no order.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public async Task ValidHelloYieldsItsMetadata()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Equal(
            VectorChannel.ValidMetadata.OrderBy(entry => entry.Key, StringComparer.Ordinal),
            result.Metadata.OrderBy(entry => entry.Key, StringComparer.Ordinal));
    }

    // Metadata may be an empty object.
    // A protobuf map without entries is also how a Hello without metadata arrives,
    // so the rule that rejects a JSON body without metadata cannot apply here.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public async Task HelloWithoutMetadataSucceeds()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        hello.Hello.Metadata.Clear();

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Empty(result.Metadata);
    }

    // CONTRACT.agent-identity.md §7.3 step 4: Welcome has correlation_id = Hello id.
    // CONTRACT.agent-identity.md §1 and §7.3: envelope ids are lowercase hyphenated UUIDs.
    // The Hello id is in uppercase, so a Welcome that normalized it would no longer match what the agent sent.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public async Task WelcomeAnswersTheHello()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        hello.Id = NewId().ToUpperInvariant();

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
        ServerMessage welcome = result.Welcome;
        Assert.Equal(ServerMessage.PayloadOneofCase.Welcome, welcome.PayloadCase);
        Assert.Matches(UuidPattern, welcome.Id);
        Assert.NotEqual(opening.Challenge.Id, welcome.Id);
        Assert.True(welcome.HasCorrelationId);
        Assert.Equal(hello.Id, welcome.CorrelationId);
    }

    // Step 4: the server replies Welcome when it verifies the Hello, and the schema's Welcome carries server_time.
    // The clock stands still at an instant after the opening, with a fraction of a second,
    // so whenever the handshake reads it, that instant is the server's time.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task WelcomeCarriesTheServerTime()
    {
        FixedTimeProvider clock = new(VectorChannel.OpeningTime);
        ChannelOpening opening = await VectorChannel.OpenAsync(clock);
        DateTimeOffset answered = VectorChannel.OpeningTime.AddMilliseconds(3_250);
        clock.Now = answered;

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Equal(Timestamp.FromDateTimeOffset(answered), result.Welcome.Welcome.ServerTime);
    }

    // Step 3: the Hello answers the Challenge id, with a proof over the challenge bytes.
    // The agent answers the Challenge it received, so the handshake holds the Hello to the id and bytes as sent,
    // even if the host later edits the message object it sent.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task HandshakeChecksTheChallengeAsSent()
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        AgentMessage hello = VectorChannel.ValidHelloMessage(opening);
        opening.Challenge.Id = NewId();
        opening.Challenge.Challenge.Challenge_ = ByteString.CopyFrom(new byte[32]);

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
    }

    // A certificate is unexpired while now ≤ notAfter, compared to the exact instant.
    // The Welcome shows that the clock reading that judged the certificate is the one at notAfter.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    [Fact]
    public async Task HandshakeSucceedsAtTheCertificateNotAfter()
    {
        (ChannelOpening opening, AgentMessage hello) = await OpenBeforeNotAfterAsync(DeviceANotAfter);

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(hello);

        Assert.True(result.Succeeded, result.FailureDetail);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
        Assert.Equal(Timestamp.FromDateTimeOffset(DeviceANotAfter), result.Welcome.Welcome.ServerTime);
    }

    // CONTRACT.agent-identity.md §6: a certificate is unexpired while now ≤ notAfter, compared to the exact instant.
    // CONTRACT.agent-identity.md §7.4 and the shared intent, security invariant 8: a stream closes no later than the
    // notAfter of the certificate that opened it, with UNAUTHENTICATED and error-code certificate_expired,
    // even while it waits for its Hello, so the timeout fails as a timeout only until then.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData("a valid Hello", 1, AgentIdentityErrorCode.CertificateExpired)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [InlineData("no Hello in time", 0, AgentIdentityErrorCode.SignatureInvalid)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData("no Hello in time", 1, AgentIdentityErrorCode.CertificateExpired)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [InlineData("the first message could not be decoded", 0, AgentIdentityErrorCode.SignatureInvalid)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData("the first message could not be decoded", 1, AgentIdentityErrorCode.CertificateExpired)]
    public async Task HandshakeIsCertificateExpiredOnlyAfterTheNotAfter(
        string end,
        long ticksAfterNotAfter,
        AgentIdentityErrorCode expectedCode)
    {
        (ChannelOpening opening, AgentMessage hello) =
            await OpenBeforeNotAfterAsync(DeviceANotAfter.AddTicks(ticksAfterNotAfter));

        ChannelHandshakeResult result = await HandshakeEndsBeforeNotAfter[end](opening, hello);

        AssertFailed(result, expectedCode, StatusCode.Unauthenticated);
    }

    // Step 4: the server waits 10 s for the Hello.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public void HelloTimeoutIs10Seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(10), ChannelHandshake.HelloTimeout);
    }

    // Step 4: the Hello must arrive within 10 s of the opening, 10 s included.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task HelloExactlyAtTheTimeoutSucceeds()
    {
        DateTimeOffset opened = VectorChannel.OpeningTime;
        DateTimeOffset answered = opened.AddSeconds(10);
        ChannelOpening opening = await VectorChannel.OpenAsync(
            new SteppingTimeProvider(opened, opened, answered, answered.AddTicks(1)));

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
    }

    // Steps 1 and 2: the agent sends nothing until it receives the Challenge,
    // which the server sends once it has verified the opening request.
    // The agent can answer only once the opening is verified and its challenge sent,
    // so the 10 s run from the end of verification, not from the earlier reading that judged the request.
    // Here the registry and the nonce store take 5 s, and the Hello comes 10 s after them.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Fact]
    public async Task HelloTimeoutRunsFromTheEndOfTheOpening()
    {
        DateTimeOffset judged = VectorChannel.OpeningTime;
        DateTimeOffset verified = judged.AddSeconds(5);
        ChannelOpening opening = await VectorChannel.OpenAsync(
            new SteppingTimeProvider(judged, verified, verified.AddSeconds(10)));

        ChannelHandshakeResult result = await opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening));

        Assert.True(result.Succeeded, result.FailureDetail);
    }

    // The first agent message decides the stream: a second one could retry a failed proof,
    // and a late Hello could authenticate a stream that already timed out.
    // CONTRACT.agent-identity.md §7.3 step 4 decides a stream by its first agent message or by the timeout, not both,
    // so a valid Hello after the handshake ended yields no identity, whether the call throws or returns.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Theory]
    [MemberData(nameof(HandshakeEndNames))]
    public async Task ValidHelloAfterTheHandshakeEndedYieldsNoIdentity(string end)
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        await HandshakeEnds[end](opening);

        await AssertYieldsNoIdentityAsync(() => opening.VerifyHelloAsync(VectorChannel.ValidHelloMessage(opening)));
    }

    // The first call that ends the handshake takes its single-use slot,
    // so a later call to FirstMessageUnreadableAsync refuses instead of returning a result.
    // oracle: mutant a call to FirstMessageUnreadableAsync after the handshake ended that returns a result
    // instead of refusing
    [Theory]
    [MemberData(nameof(HandshakeEndNames))]
    public async Task FirstMessageUnreadableAfterTheHandshakeEndedYieldsNoResult(string end)
    {
        ChannelOpening opening = await VectorChannel.OpenAsync();
        await HandshakeEnds[end](opening);
        ChannelHandshakeResult? result = null;

        _ = await Record.ExceptionAsync(async () => result = await opening.FirstMessageUnreadableAsync());

        Assert.Null(result);
    }

    // CONTRACT.agent-identity.md §7.3 step 4 and §7.4: the server closes the stream with the gRPC status of the failure
    // and the trailers `error-code: <§5.4 code>` and `server-time: <RFC 3339>`, which the agent reads.
    // The contract states no order for the trailers.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Theory]
    [InlineData("a Hello with the proof of another device", StatusCode.Unauthenticated, "signature_invalid")]
    [InlineData("a Hello with invalid metadata", StatusCode.InvalidArgument, "invalid_request")]
    [InlineData("no Hello in time", StatusCode.Unauthenticated, "signature_invalid")]
    [InlineData("the first message could not be decoded", StatusCode.Unauthenticated, "signature_invalid")]
    public async Task FailureClosesTheStreamWithTheContractStatusAndTrailers(
        string end,
        StatusCode expectedStatus,
        string expectedCode)
    {
        DateTimeOffset serverTime = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
        ChannelOpening opening = await VectorChannel.OpenAsync();
        ChannelHandshakeResult result = await HandshakeEnds[end](opening);
        Assert.False(result.Succeeded);

        RpcException exception = result.Error.ToRpcException(serverTime);

        Assert.Equal(expectedStatus, exception.StatusCode);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        Assert.Equal(
            [("error-code", expectedCode), ("server-time", "2026-09-24T12:00:00Z")],
            exception.Trailers
                .Select(entry => (entry.Key, entry.Value))
                .OrderBy(entry => entry.Key, StringComparer.Ordinal));
    }

    // Asserts that the handshake failed with the code and the gRPC status, and returns its error.
    private static AgentIdentityError AssertFailed(
        ChannelHandshakeResult result,
        AgentIdentityErrorCode expectedCode,
        StatusCode expectedStatus)
    {
        Assert.False(result.Succeeded);
        Assert.Equal(expectedCode, result.Error.Code);
        Assert.Equal(expectedStatus, result.Error.ToRpcException(DateTimeOffset.UnixEpoch).StatusCode);
        // oracle: mutant an empty failure detail for a late Hello, a first message that is not a Hello,
        // a Hello without a correlation_id or correlated to another id, a proof that does not verify,
        // no Hello before the timeout, a first message that could not be decoded, a certificate no longer registered,
        // or a revoked identity
        Assert.False(string.IsNullOrEmpty(result.FailureDetail));
        return result.Error;
    }

    // Asserts that the call yields no identity, whether it throws or returns.
    private static async Task AssertYieldsNoIdentityAsync(Func<ValueTask<ChannelHandshakeResult>> call)
    {
        ChannelHandshakeResult? result = null;

        _ = await Record.ExceptionAsync(async () => result = await call());

        Assert.Null(result?.Identity);
    }

    private static AgentMessage Altered(AgentMessage message, Action<AgentMessage> alteration)
    {
        alteration(message);
        return message;
    }

    // Pairs each failure with every failure after it in the order, then with each failure checked after all of them,
    // and fails both by combining their scenarios.
    private static void AddOrderedPairs(
        Dictionary<(string Earlier, string Later), Scenario> pairs,
        string[] ordered,
        IEnumerable<string> checkedAfter)
    {
        for (int i = 0; i < ordered.Length; i++)
        {
            foreach (string later in ordered.Skip(i + 1).Concat(checkedAfter))
            {
                pairs.Add((ordered[i], later), Scenarios[ordered[i]].And(Scenarios[later]));
            }
        }
    }

    // The name of the failure of a stream that ends with no Hello, and that the closure ends first.
    private static string WithClosure(string end, string closure)
    {
        return $"{end}, and {closure}";
    }

    // Opens the vector stream, changes the registry and the clock as the scenario says,
    // then ends the handshake with its first message.
    private static async Task<ChannelHandshakeResult> HandshakeAsync(
        Scenario scenario,
        VectorAuthority? authority = null)
    {
        authority ??= new VectorAuthority();
        DateTimeOffset opened = VectorChannel.OpeningTime;
        ChannelOpening opening = await VectorChannel.OpenAsync(
            authority,
            new SteppingTimeProvider(opened, opened, scenario.HandshakeTime ?? opened));

        if (scenario.CertificateRemoved)
        {
            authority.Registry.Unregister(opening.CertificateThumbprint);
        }
        else
        {
            VectorChannel.RegisterDevice(authority.Registry, scenario.Status, scenario.IdentityRevoked);
        }

        if (scenario.FirstMessageUnreadable)
        {
            return await opening.FirstMessageUnreadableAsync();
        }

        return scenario.FirstMessage is { } firstMessage
            ? await opening.VerifyHelloAsync(firstMessage(opening))
            : await opening.HelloTimedOutAsync();
    }

    // Opens a stream five seconds before the certificate of device-a expires, with a valid Hello signed for it,
    // so that the handshake can reach notAfter within the Hello timeout.
    // The clock reads the opening's time to judge the request and to start the timeout, then handshakeTime.
    private static async Task<(ChannelOpening Opening, AgentMessage Hello)> OpenBeforeNotAfterAsync(
        DateTimeOffset handshakeTime)
    {
        DateTimeOffset opened = DeviceANotAfter.AddSeconds(-5);
        TestAuthority authority = new(opened, clock: new SteppingTimeProvider(opened, opened, handshakeTime));
        SignedHttpRequest request = authority.Valid(AgentOperation.Connect).ToHttpRequest();

        ChannelOpeningResult result = await authority.Authenticator.AuthenticateChannelOpeningAsync(
            request.Method,
            request.SignatureInput,
            request.Signature);

        Assert.True(result.Succeeded, result.FailureDetail);
        ChannelOpening opening = result.Opening;
        byte[] proof = TestChannelProof.Sign(
            DeviceA,
            opening.Challenge.Challenge.Challenge_.Span,
            TestRequest.DefaultNonce);

        return (opening, VectorChannel.HelloMessage(opening, proof));
    }

    // Opens the vector stream as VectorChannel.OpenAsync does, but over the given registry.
    private static async Task<ChannelOpening> OpenAsync(ICertificateRegistry registry)
    {
        ChannelProofVectors vectors = TestVectors.Instance.ChannelProof;
        HttpSignatureCaseVector connect = TestVectors.Instance.HttpSignature.Case(vectors.ConnectCase);
        RequestAuthenticator authenticator = new(
            registry,
            new RecordingNonceStore(),
            new FixedTimeProvider(VectorChannel.OpeningTime),
            new ScriptedRandomNumberGenerator(vectors.Challenge));

        ChannelOpeningResult result = await authenticator.AuthenticateChannelOpeningAsync(
            connect.Method,
            VectorAuthority.Lines(connect.Headers.SignatureInput),
            VectorAuthority.Lines(connect.Headers.Signature));

        // oracle: reference docs/agent-identity/test-vectors.json channel_proof.connect_case
        Assert.True(result.Succeeded, result.FailureDetail);
        return result.Opening;
    }

    private static string NewId()
    {
        return Guid.NewGuid().ToString("D");
    }

    // A handshake on the vector stream: what the registry holds and what the clock reads by then,
    // and the first message, a valid Hello unless the scenario says otherwise.
    private sealed record Scenario
    {
        public bool CertificateRemoved { get; init; }

        public bool IdentityRevoked { get; init; }

        public CertificateStatus Status { get; init; } = CertificateStatus.Current;

        // The time of the opening when null.
        public DateTimeOffset? HandshakeTime { get; init; }

        // When null, no message arrives and the host ends the handshake for the timeout.
        public Func<ChannelOpening, AgentMessage>? FirstMessage { get; init; } = VectorChannel.ValidHelloMessage;

        // When true, the first message arrives but cannot be decoded, and FirstMessage is not used.
        public bool FirstMessageUnreadable { get; init; }

        // This scenario with the changes of a later one to the registry and the clock, and with its first message.
        // The only clock readings combined are after notAfter and after the timeout, and the first is after both.
        public Scenario And(Scenario later)
        {
            return new Scenario
            {
                CertificateRemoved = CertificateRemoved || later.CertificateRemoved,
                IdentityRevoked = IdentityRevoked || later.IdentityRevoked,
                Status = Status,
                HandshakeTime = HandshakeTime ?? later.HandshakeTime,
                FirstMessage = later.FirstMessage,
                FirstMessageUnreadable = later.FirstMessageUnreadable,
            };
        }
    }

    // A scenario that fails the handshake, with the code and the gRPC status that close the stream.
    private sealed record Failure(Scenario Scenario, AgentIdentityErrorCode Code, StatusCode Status);

    // The registry of the vector authority, which records for each lookup whether the host had already added the
    // stream to its live streams.
    private sealed class LiveStreamRecordingRegistry : ICertificateRegistry
    {
        private readonly FakeCertificateRegistry _registry = new VectorAuthority().Registry;

        public bool StreamAdded { get; set; }

        public List<bool> StreamAddedAtLookups { get; } = [];

        public ValueTask<RegisteredCertificate?> FindByThumbprintAsync(
            string thumbprint,
            CancellationToken cancellationToken)
        {
            StreamAddedAtLookups.Add(StreamAdded);
            return _registry.FindByThumbprintAsync(thumbprint, cancellationToken);
        }
    }
}
