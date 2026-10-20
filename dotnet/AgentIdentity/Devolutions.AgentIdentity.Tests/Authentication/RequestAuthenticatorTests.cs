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

    public static TheoryData<AgentOperation> Operations => new(Enum.GetValues<AgentOperation>());

    public static TheoryData<AgentOperation> OperationsWithoutRenewalGrace =>
        new(AgentOperation.Confirm, AgentOperation.CheckIn, AgentOperation.Connect);

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

    public static TheoryData<CertificateStatus> AcceptedStatuses =>
        new(CertificateStatus.Pending, CertificateStatus.Current);

    public static TheoryData<string> OversizedRequestNames => new(OversizedRequests.Keys);

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
    // so the identity's state is reported even when the signature would not verify.
    // In these tests, device-b signs for the keyid of device-a.
    [Fact]
    public async Task RevokedIdentityWinsOverABadSignature()
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(DeviceA, identityRevoked: true);

        string outcome = await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew) with { Key = DeviceB });

        Assert.Equal("identity_revoked", outcome);
    }

    [Fact]
    public async Task RetiredCertificateWinsOverABadSignature()
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(DeviceA, CertificateStatus.Retired);

        string outcome = await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew) with { Key = DeviceB });

        Assert.Equal("identity_unknown", outcome);
    }

    [Fact]
    public async Task ExpiredCertificateWinsOverABadSignature()
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter.AddSeconds(1));

        string outcome = await authority.OutcomeAsync(authority.Valid(AgentOperation.Confirm) with { Key = DeviceB });

        Assert.Equal("certificate_expired", outcome);
    }

    // The body changes after signing, so only its digest fails.
    [Fact]
    public async Task CertificateBeyondRenewalGraceWinsOverABodyThatDoesNotMatchItsDigest()
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter + DeviceALifetime);
        TestRequest request = authority.Valid(AgentOperation.Renew) with { Body = [0x7B, 0x7D] };

        Assert.Equal("certificate_expired", await authority.OutcomeAsync(request));
    }

    // CONTRACT.md §6 step 4 resolves the certificate before it reads the identity's revocation,
    // and reads revocation before validity, so a revoked identity always draws the terminal identity_revoked.
    [Fact]
    public async Task RetiredCertificateWinsOverRevocation()
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(DeviceA, CertificateStatus.Retired, identityRevoked: true);

        Assert.Equal("identity_unknown", await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew)));
    }

    [Fact]
    public async Task RevocationWinsOverExpiry()
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter.AddSeconds(1));
        authority.Registry.Register(DeviceA, identityRevoked: true);

        Assert.Equal("identity_revoked", await authority.OutcomeAsync(authority.Valid(AgentOperation.Confirm)));
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

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task RetiredCertificateIsIdentityUnknown(AgentOperation operation)
    {
        TestAuthority authority = new(Now);
        authority.Registry.Register(DeviceA, CertificateStatus.Retired);

        Assert.Equal("identity_unknown", await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // CONTRACT.md §6: a certificate is unexpired while now ≤ notAfter, compared to the exact instant.
    [Theory]
    [MemberData(nameof(Operations))]
    public async Task CertificateIsAcceptedAtItsNotAfter(AgentOperation operation)
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter);

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(operation)));
    }

    // A clock truncated to the second would still accept the certificate here.
    [Theory]
    [MemberData(nameof(OperationsWithoutRenewalGrace))]
    public async Task CertificateIsExpiredOneTickAfterItsNotAfter(AgentOperation operation)
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter.AddTicks(1));

        Assert.Equal("certificate_expired", await authority.OutcomeAsync(authority.Valid(operation)));
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
    [MemberData(nameof(AcceptedStatuses))]
    public async Task RenewAcceptsACertificateOneTickAfterItsNotAfter(CertificateStatus status)
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter.AddTicks(1));
        authority.Registry.Register(DeviceA, status);

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew)));
    }

    [Theory]
    [MemberData(nameof(AcceptedStatuses))]
    public async Task RenewAcceptsACertificateOneTickBeforeItsGraceEnds(CertificateStatus status)
    {
        TestAuthority authority = new((DeviceACertificate.NotAfter + DeviceALifetime).AddTicks(-1));
        authority.Registry.Register(DeviceA, status);

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew)));
    }

    [Theory]
    [MemberData(nameof(AcceptedStatuses))]
    public async Task RenewRejectsACertificateWhenItsGraceEnds(CertificateStatus status)
    {
        TestAuthority authority = new(DeviceACertificate.NotAfter + DeviceALifetime);
        authority.Registry.Register(DeviceA, status);

        Assert.Equal("certificate_expired", await authority.OutcomeAsync(authority.Valid(AgentOperation.Renew)));
    }

    // A second reading of the clock between the window and the certificate check
    // would judge the certificate a day later, after it expired.
    [Fact]
    public async Task WindowAndCertificateAreJudgedAtOneReadingOfTheClock()
    {
        DateTimeOffset first = DeviceACertificate.NotAfter;
        TestAuthority authority = new(first, clock: new SteppingTimeProvider(first, first.AddDays(1)));

        Assert.Equal("ok", await authority.OutcomeAsync(authority.Valid(AgentOperation.Confirm)));
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

    // The shared intent, security invariant 7: signed opening headers never authenticate a stream on their own.
    // An uninitialized operation names no endpoint, so it authenticates nothing either.
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
    // The keyid is the thumbprint of those bytes, so the registry answers with what it was asked for.
    [Theory]
    [InlineData("a P-384 certificate")]
    [InlineData("an RSA certificate")]
    [InlineData("bytes that are not a certificate")]
    public async Task RegistryReturningSomethingOtherThanAP256CertificateThrows(string registered)
    {
        byte[] der = registered switch
        {
            "a P-384 certificate" => SelfSignedP384Certificate(),
            "an RSA certificate" => SelfSignedRsaCertificate(),
            _ => [0x30, 0x00],
        };
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
