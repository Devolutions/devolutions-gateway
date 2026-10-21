using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The steps of CONTRACT.md §6 after parsing: their order, the certificate rules, the nonce, and the host's part.
/// </summary>
public class RequestAuthenticatorTests
{
    // CONTRACT.md §5.4: servers accept request bodies up to 64 KiB.
    private const int OverTheLimit = (64 * 1024) + 1;

    private static readonly DateTimeOffset Now = TestAuthority.DefaultNow;

    private static readonly Dictionary<string, Func<TestAuthority, SignedHttpRequest>> OversizedRequests = new()
    {
        ["with a malformed signature"] = _ =>
            new SignedHttpRequest("POST", ["not a signature"], [], [], new byte[OverTheLimit]),
        ["correctly signed"] = authority =>
        {
            byte[] body = new byte[OverTheLimit];
            TestRequest request = authority.Valid(AgentOperation.Renew) with
            {
                Body = body,
                ContentDigest = TestRequest.Sha256Digest(body),
            };
            return request.ToHttpRequest();
        },
    };

    // Each request fails the two checks its key names.
    // For a wrong key, device-b signs for the keyid of device-a;
    // for a wrong digest, the body changes after signing, so only its digest fails.
    private static readonly Dictionary<string, Func<(TestAuthority Authority, TestRequest Request)>> TwoFailures =
        new()
        {
            ["revoked identity, wrong key"] = () =>
            {
                TestAuthority authority = new(Now);
                authority.Registry.Register(DeviceA, identityRevoked: true);
                return (authority, authority.Valid(AgentOperation.Renew) with { Key = DeviceB });
            },
            ["retired certificate, wrong key"] = () =>
            {
                TestAuthority authority = new(Now);
                authority.Registry.Register(DeviceA, CertificateStatus.Retired);
                return (authority, authority.Valid(AgentOperation.Renew) with { Key = DeviceB });
            },
            ["expired certificate, wrong key"] = () =>
            {
                TestAuthority authority = new(DeviceACertificate.NotAfter.AddSeconds(1));
                return (authority, authority.Valid(AgentOperation.Confirm) with { Key = DeviceB });
            },
            ["beyond renewal grace, wrong digest"] = () =>
            {
                TestAuthority authority = new(DeviceACertificate.NotAfter + DeviceALifetime);
                return (authority, authority.Valid(AgentOperation.Renew) with { Body = [0x7B, 0x7D] });
            },
            ["retired certificate, revoked identity"] = () =>
            {
                TestAuthority authority = new(Now);
                authority.Registry.Register(DeviceA, CertificateStatus.Retired, identityRevoked: true);
                return (authority, authority.Valid(AgentOperation.Renew));
            },
            ["expired certificate, revoked identity"] = () =>
            {
                TestAuthority authority = new(DeviceACertificate.NotAfter.AddSeconds(1));
                authority.Registry.Register(DeviceA, identityRevoked: true);
                return (authority, authority.Valid(AgentOperation.Confirm));
            },
        };

    // The renewal grace of device-a's certificate ends at notAfter + (notAfter − notBefore).
    private static readonly Dictionary<string, Func<DateTimeOffset>> RenewalGraceInstants = new()
    {
        ["one tick after notAfter"] = () => DeviceACertificate.NotAfter.AddTicks(1),
        ["one tick before grace ends"] = () => (DeviceACertificate.NotAfter + DeviceALifetime).AddTicks(-1),
        ["when grace ends"] = () => DeviceACertificate.NotAfter + DeviceALifetime,
    };

    private static readonly Dictionary<string, Func<byte[]>> RegisteredBytesOtherThanAP256Certificate = new()
    {
        ["a P-384 certificate"] = SelfSignedP384Certificate,
        ["an RSA certificate"] = SelfSignedRsaCertificate,
        ["bytes that are not a certificate"] = () => [0x30, 0x00],
    };

    public static TheoryData<AgentOperation> Operations => new(Enum.GetValues<AgentOperation>());

    public static TheoryData<AgentOperation, CertificateStatus> OperationsWithAcceptedStatuses
    {
        get
        {
            TheoryData<AgentOperation, CertificateStatus> cases = new();

            foreach (AgentOperation operation in Enum.GetValues<AgentOperation>())
            {
                cases.Add(operation, CertificateStatus.Pending);
                cases.Add(operation, CertificateStatus.Current);
            }

            return cases;
        }
    }

    public static TheoryData<string> OversizedRequestNames => new(OversizedRequests.Keys);

    public static TheoryData<string> RegisteredBytesOtherThanAP256CertificateNames =>
        new(RegisteredBytesOtherThanAP256Certificate.Keys);

    private static KeyVector DeviceA => TestVectors.Instance.Key("device-a");

    private static KeyVector DeviceB => TestVectors.Instance.Key("device-b");

    // The validity of the certificate of device-a, as the vector file states it.
    private static RegisteredCertificateVector DeviceACertificate =>
        TestVectors.Instance.HttpSignature.RegisteredCertificate("device-a");

    private static TimeSpan DeviceALifetime => DeviceACertificate.NotAfter - DeviceACertificate.NotBefore;

    // CONTRACT.md §5.4: a body larger than 64 KiB returns 413 invalid_request before any authentication outcome.
    [Theory]
    [MemberData(nameof(OversizedRequestNames))]
    public async Task BodyOverTheLimitIsRejectedWith413First(string request)
    {
        TestAuthority authority = new(Now);

        AuthenticationResult result = await authority.Authenticator.AuthenticateAsync(
            AgentOperation.Renew,
            OversizedRequests[request](authority));

        Assert.False(result.Succeeded);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, result.Error.Code);
        Assert.Equal(413, result.Error.HttpStatusCode);
        Assert.Empty(authority.Registry.Lookups);
        Assert.Empty(authority.Nonces.Calls);
    }

    // CONTRACT.md §5.4: servers accept request bodies up to 64 KiB.
    [Fact]
    public async Task BodyOfExactlyTheLimitIsAccepted()
    {
        TestAuthority authority = new(Now);
        byte[] body = new byte[OverTheLimit - 1];
        TestRequest request = authority.Valid(AgentOperation.Renew) with
        {
            Body = body,
            ContentDigest = TestRequest.Sha256Digest(body),
        };

        Assert.Equal("ok", await authority.OutcomeAsync(request));
    }

    // CONTRACT.md §6: the earliest failing step decides,
    // so the identity's state is reported even when the signature or the digest would not verify.
    [Theory]
    [InlineData("revoked identity, wrong key", "identity_revoked")]
    [InlineData("retired certificate, wrong key", "identity_unknown")]
    [InlineData("expired certificate, wrong key", "certificate_expired")]
    [InlineData("beyond renewal grace, wrong digest", "certificate_expired")]
    public async Task StepFourFailureWinsOverAStepFiveFailure(string request, string expected)
    {
        (TestAuthority authority, TestRequest failing) = TwoFailures[request]();

        Assert.Equal(expected, await authority.OutcomeAsync(failing));
    }

    // CONTRACT.md §6 step 4 resolves the certificate before it reads the identity's revocation,
    // and reads revocation before validity, so a revoked identity always draws the terminal identity_revoked.
    [Theory]
    [InlineData("retired certificate, revoked identity", "identity_unknown")]
    [InlineData("expired certificate, revoked identity", "identity_revoked")]
    public async Task StepFourReturnsItsEarliestFailingCheck(string request, string expected)
    {
        (TestAuthority authority, TestRequest failing) = TwoFailures[request]();

        Assert.Equal(expected, await authority.OutcomeAsync(failing));
    }

    // CONTRACT.md §6 table: every operation accepts a current or pending certificate.
    [Theory]
    [MemberData(nameof(OperationsWithAcceptedStatuses))]
    public async Task PendingOrCurrentCertificateIsAccepted(AgentOperation operation, CertificateStatus status)
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(DeviceA, status);

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // CONTRACT.md §6 step 4: a certificate that is neither current nor pending draws identity_unknown.
    [Theory]
    [MemberData(nameof(Operations))]
    public async Task RetiredCertificateIsIdentityUnknown(AgentOperation operation)
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(DeviceA, CertificateStatus.Retired);

        Assert.Equal("identity_unknown", await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // CONTRACT.md §6: a certificate is unexpired while now ≤ notAfter, compared to the exact instant.
    // A clock truncated to the second would still accept the certificate one tick after its notAfter.
    // Renew has no row one tick after, because its grace still accepts the certificate then.
    [Theory]
    [InlineData(AgentOperation.Renew, 0, "ok")]
    [InlineData(AgentOperation.Confirm, 0, "ok")]
    [InlineData(AgentOperation.CheckIn, 0, "ok")]
    [InlineData(AgentOperation.Connect, 0, "ok")]
    [InlineData(AgentOperation.Confirm, 1, "certificate_expired")]
    [InlineData(AgentOperation.CheckIn, 1, "certificate_expired")]
    [InlineData(AgentOperation.Connect, 1, "certificate_expired")]
    public async Task CertificateExpiresAfterTheExactInstantOfItsNotAfter(
        AgentOperation operation,
        int ticksAfterNotAfter,
        string expected)
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter.AddTicks(ticksAfterNotAfter));

        Assert.Equal(expected, await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // CONTRACT.md §6: notBefore is not checked,
    // so a certificate dated by a fast authority clock does not lock devices out.
    [Theory]
    [MemberData(nameof(Operations))]
    public async Task CertificateIsAcceptedBeforeItsNotBefore(AgentOperation operation)
    {
        TestAuthority authority = new(DeviceACertificate.NotBefore.AddTicks(-1));

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // CONTRACT.md §6 table: renew accepts a certificate while now < notAfter + (notAfter − notBefore).
    [Theory]
    [InlineData(CertificateStatus.Pending, "one tick after notAfter", "ok")]
    [InlineData(CertificateStatus.Current, "one tick after notAfter", "ok")]
    [InlineData(CertificateStatus.Pending, "one tick before grace ends", "ok")]
    [InlineData(CertificateStatus.Current, "one tick before grace ends", "ok")]
    [InlineData(CertificateStatus.Pending, "when grace ends", "certificate_expired")]
    [InlineData(CertificateStatus.Current, "when grace ends", "certificate_expired")]
    public async Task RenewGraceIsTheCertificateLifetimeAfterItsNotAfter(
        CertificateStatus status,
        string instant,
        string expected)
    {
        TestAuthority authority = new(RenewalGraceInstants[instant]());
        authority.Registry.Register(DeviceA, status);

        Assert.Equal(expected, await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew)));
    }

    // CONTRACT.md §6 states the window of step 3 and the certificate rule of step 4 against the same `now`.
    // A second reading of the clock between the window and the certificate check
    // would judge the certificate a day later, after it expired.
    [Fact]
    public async Task WindowAndCertificateAreJudgedAtOneReadingOfTheClock()
    {
        DateTimeOffset first = DeviceACertificate.NotAfter;
        TestAuthority authority = new(first, clock: new SteppingTimeProvider(first, first.AddDays(1)));

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(AgentOperation.Confirm)));
    }

    // CONTRACT.md §6 step 3: 0 < expires − created ≤ 300.
    [Fact]
    public async Task SignatureLifetimeOf300SecondsIsAccepted()
    {
        TestAuthority authority = new(Now);
        string expires = (Now.ToUnixTimeSeconds() + 300).ToString(CultureInfo.InvariantCulture);

        string outcome = await authority.OutcomeAsync(
            authority.Valid(AgentOperation.Confirm).WithParameter("expires", expires));

        Assert.Equal("ok", outcome);
    }

    // RFC 8941 §3.3.1: an integer may be negative, and RFC 9421 §2.3 serializes it with its sign.
    // At the Unix epoch, all three inequalities of CONTRACT.md §6 step 3 hold,
    // and the certificate of device-a, whose notBefore is later, is accepted because §6 does not check notBefore.
    [Fact]
    public async Task CreatedBeforeTheUnixEpochIsAccepted()
    {
        TestAuthority authority = new(DateTimeOffset.UnixEpoch);
        TestRequest request = authority.Valid(AgentOperation.Confirm)
            .WithParameter("created", "-1")
            .WithParameter("expires", "59");

        Assert.Equal("ok", await authority.OutcomeAsync(request));
    }

    // CONTRACT.md §6: the earliest failing step decides.
    // RFC 8941 §3.3.5 allows a byte sequence of no bytes, in its canonical base64 of no characters,
    // so the signature passes step 1 and its length fails only step 5, after the window of step 3.
    [Fact]
    public async Task SignatureOfNoBytesIsJudgedAfterTheWindow()
    {
        TestAuthority authority = new(Now);
        string expires = (Now.ToUnixTimeSeconds() + 301).ToString(CultureInfo.InvariantCulture);
        TestRequest request = authority.Valid(AgentOperation.Confirm).WithParameter("expires", expires);

        string outcome = await authority.OutcomeAsync(
            AgentOperation.Confirm,
            request.ToHttpRequest(signature: ["sig=::"]));

        Assert.Equal("clock_skew", outcome);
    }

    // CONTRACT.md §6 step 6: a pair the store already holds fails, whichever request recorded it.
    [Theory]
    [MemberData(nameof(Operations))]
    public async Task NonceAlreadyRecordedIsSignatureInvalid(AgentOperation operation)
    {
        TestAuthority authority = new(Now, new RecordingNonceStore { AnswerAlreadyRecorded = true });

        Assert.Equal("signature_invalid", await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // CONTRACT.md §6: a header the operation does not cover, such as Content-Digest on confirm, is ignored.
    [Fact]
    public async Task ConfirmIgnoresContentDigest()
    {
        TestAuthority authority = new(Now);
        TestRequest confirm = authority.Valid(AgentOperation.Confirm);

        string outcome = await authority.OutcomeAsync(
            AgentOperation.Confirm,
            confirm.ToHttpRequest(contentDigest: ["(not a dictionary"]));

        Assert.Equal("ok", outcome);
    }

    // RFC 9110 §9.1: a method is a token, and anything else could put a line break of its own into the signature base.
    [Theory]
    [InlineData("")]
    [InlineData("PO ST")]
    [InlineData("POST\n")]
    public async Task MethodThatIsNotATokenIsSignatureInvalid(string method)
    {
        TestAuthority authority = new(Now);

        string outcome = await authority.OutcomeAsync(authority.Valid(AgentOperation.Confirm) with { Method = method });

        Assert.Equal("signature_invalid", outcome);
    }

    // A method that is not a token gives @method no value, so no signature base exists to verify,
    // not even an empty one: RFC 9421 §2.5 ends every base with its @signature-params line.
    [Fact]
    public async Task MethodThatIsNotATokenCannotVerifyASignatureOverNoBytes()
    {
        TestAuthority authority = new(Now);
        TestRequest request = authority.Valid(AgentOperation.Confirm) with { Method = "" };
        using ECDsa key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(request.Key.PrivateKeyPkcs8, out _);
        byte[] signature = key.SignData(
            [],
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        string outcome = await authority.OutcomeAsync(
            AgentOperation.Confirm,
            request.ToHttpRequest(signature: [$"sig=:{Convert.ToBase64String(signature)}:"]));

        Assert.Equal("signature_invalid", outcome);
    }

    // RFC 9110 §5.6.2: a token may hold any of these punctuation characters, besides letters and digits.
    [Fact]
    public async Task MethodWithEveryTokenPunctuationCharacterIsAccepted()
    {
        TestAuthority authority = new(Now);

        string outcome = await authority.OutcomeAsync(
            authority.Valid(AgentOperation.Confirm) with { Method = "A!#$%&'*+-.^_`|~" });

        Assert.Equal("ok", outcome);
    }

    // The shared intent, security invariant 7: signed opening headers never authenticate a stream on their own.
    // An uninitialized operation names no endpoint, so it authenticates nothing either.
    // Framework Design Guidelines, Parameter Design: validate enum parameters, since an enum may hold any integer.
    [Theory]
    [InlineData(AgentOperation.Connect)]
    [InlineData((AgentOperation)0)]
    [InlineData((AgentOperation)5)]
    public async Task AuthenticateAsyncRefusesAnOperationThatIsNotASignedHttpRequest(AgentOperation operation)
    {
        TestAuthority authority = new(Now);
        SignedHttpRequest request = authority.Valid(AgentOperation.Connect).ToHttpRequest();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => authority.Authenticator.AuthenticateAsync(operation, request).AsTask());
        Assert.Empty(authority.Nonces.Calls);
    }

    // The registry answers by thumbprint, so another certificate is a host bug,
    // which must fail as a server error rather than draw an outcome the agent acts on.
    // CONTRACT.md §5.4: identity_unknown is terminal for the agent, so a host bug must not draw it.
    [Fact]
    public async Task RegistryReturningACertificateWithAnotherThumbprintThrows()
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(
            DeviceA.Thumbprint,
            new RegisteredCertificate(DeviceB.IdentityId, DeviceB.Certificate, CertificateStatus.Current, false));
        SignedHttpRequest request = authority.Valid(AgentOperation.Renew).ToHttpRequest();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => authority.Authenticator.AuthenticateAsync(AgentOperation.Renew, request).AsTask());
    }

    // CONTRACT.md §4: the authority issues P-256 leaves only, so any other registered bytes are a host bug.
    // CONTRACT.md §5.4: identity_unknown is terminal for the agent, so a host bug must not draw it.
    // The keyid is the thumbprint of those bytes, so the registry answers with what it was asked for.
    [Theory]
    [MemberData(nameof(RegisteredBytesOtherThanAP256CertificateNames))]
    public async Task RegistryReturningSomethingOtherThanAP256CertificateThrows(string registered)
    {
        byte[] der = RegisteredBytesOtherThanAP256Certificate[registered]();
        string thumbprint = Base64Forms.Base64Url(SHA256.HashData(der));
        TestAuthority authority = new(Now);
        authority.Registry.Register(
            thumbprint,
            new RegisteredCertificate(Guid.NewGuid(), der, CertificateStatus.Current, false));
        SignedHttpRequest request = authority.Valid(AgentOperation.Renew)
            .WithParameter("keyid", $"\"{thumbprint}\"")
            .ToHttpRequest();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => authority.Authenticator.AuthenticateAsync(AgentOperation.Renew, request).AsTask());
    }

    private static byte[] SelfSignedP384Certificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        CertificateRequest request = new("CN=P-384", key, HashAlgorithmName.SHA384);
        using X509Certificate2 certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
        return certificate.RawData;
    }

    private static byte[] SelfSignedRsaCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=RSA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
        return certificate.RawData;
    }
}
