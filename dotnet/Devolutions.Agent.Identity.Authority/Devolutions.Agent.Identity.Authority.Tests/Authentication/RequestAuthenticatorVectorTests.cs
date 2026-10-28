using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// The shared request signature vectors, run as their <c>evaluation</c> field says.
/// </summary>
public class RequestAuthenticatorVectorTests
{
    private static HttpSignatureVectors Vectors => TestVectors.Instance.HttpSignature;

    public static TheoryData<string> OkCaseNames =>
        new(Vectors.Cases.Where(c => c.Expected == "ok").Select(c => c.Name));

    public static TheoryData<string> FailingCaseNames =>
        new(Vectors.Cases.Where(c => c.Expected != "ok").Select(c => c.Name));

    public static TheoryData<string> OkSignedRequestCaseNames =>
        new(Vectors.Cases.Where(c => c.Expected == "ok" && c.Endpoint != "connect").Select(c => c.Name));

    // Each case isolates one rule of CONTRACT.agent-identity.md §6 or its precedence,
    // so any outcome but the vector's breaks that rule.
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.cases
    [Theory]
    [MemberData(nameof(VectorData.HttpSignatureCaseNames), MemberType = typeof(VectorData))]
    public async Task CaseReturnsItsExpectedOutcome(string name)
    {
        HttpSignatureCaseVector vector = Vectors.Case(name);
        VectorAuthority authority = new();

        VectorOutcome outcome = await authority.RunAsync(vector);

        Assert.Equal(vector.Expected, outcome.Outcome);
    }

    // test-vectors.json http_signature.sequences, with CONTRACT.agent-identity.md §6 step 6.
    // A replayed nonce must fail, a nonce must survive a request that failed verification,
    // and a nonce accepted for one operation must not authenticate another.
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.sequences
    [Theory]
    [MemberData(nameof(VectorData.HttpSignatureSequenceNames), MemberType = typeof(VectorData))]
    public async Task SequenceReturnsItsExpectedOutcomes(string name)
    {
        HttpSignatureSequenceVector sequence = Vectors.Sequence(name);
        VectorAuthority authority = new();
        List<string> outcomes = [];

        foreach (string step in sequence.Steps)
        {
            outcomes.Add((await authority.RunAsync(Vectors.Case(step))).Outcome);
        }

        Assert.Equal(sequence.Expected, outcomes);
    }

    // test-vectors.json signature_base of each case, as RFC 9421 §2.5 builds it.
    // A signature base that differs from the signed one in any byte fails verification for every agent,
    // and an accepted request does not show which byte the verifier would get wrong in another request.
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.cases
    // oracle: spec RFC 9421 §2.5
    [Theory]
    [MemberData(nameof(OkCaseNames))]
    public void OkCaseSignatureBaseIsTheVectorBase(string name)
    {
        HttpSignatureCaseVector vector = Vectors.Case(name);
        SignedOperation operation = SignedOperation.For(VectorAuthority.Operation(vector.Endpoint));

        Assert.True(
            SignatureFields.TryParse(
                operation,
                VectorAuthority.Lines(vector.Headers.SignatureInput),
                VectorAuthority.Lines(vector.Headers.Signature),
                VectorAuthority.Lines(vector.Headers.ContentDigest),
                out SignatureFields? fields,
                out string? failureDetail),
            failureDetail);
        Assert.True(fields.TryBuildSignatureBase(vector.Method, out byte[]? signatureBase));
        Assert.Equal(Encoding.UTF8.GetBytes(vector.SignatureBase), signatureBase);
    }

    // RFC 9421 Appendix B.2.4 is the RFC's own ecdsa-p256-sha256 example,
    // so it fails a primitive that hashes with another algorithm or reads another signature format.
    // oracle: spec RFC 9421 §B.2.4
    // oracle: spec RFC 9421 §B.1.3
    [Fact]
    public void Rfc9421B24VerifiesWithTheLibraryPrimitive()
    {
        Rfc9421Vector vector = TestVectors.Instance.Rfc9421B24;
        using ECDsa publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(vector.PublicKeySpki, out _);
        byte[] signatureBase = Encoding.UTF8.GetBytes(vector.SignatureBase);

        bool valid = EcdsaP256Signature.Verify(publicKey, signatureBase, vector.Signature);

        Assert.Equal(vector.ExpectedValid, valid);
    }

    // Nonces are committed only after the signature verifies, so garbage requests cannot burn nonces.
    // With an empty nonce store, every failing case fails before step 6.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    [Theory]
    [MemberData(nameof(FailingCaseNames))]
    public async Task FailingCaseRecordsNoNonce(string name)
    {
        VectorAuthority authority = new();

        await authority.RunAsync(Vectors.Case(name));

        Assert.Empty(authority.Nonces.Calls);
    }

    // The failure detail goes to host logs, so a detail that echoed the request would carry text the sender chose,
    // and a captured signature, into those logs.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Failure details
    [Theory]
    [MemberData(nameof(FailingCaseNames))]
    public async Task FailingCaseDetailHoldsNoRequestData(string name)
    {
        HttpSignatureCaseVector vector = Vectors.Case(name);
        VectorAuthority authority = new();

        VectorOutcome outcome = await authority.RunAsync(vector);

        string[] headers =
        [
            .. new[] { vector.Headers.SignatureInput, vector.Headers.Signature, vector.Headers.ContentDigest }
                .OfType<string>(),
        ];
        IEnumerable<string> values = headers
            .SelectMany(header => Regex.Matches(header, "(?:keyid|nonce)=\"([^\"]+)\"|=:([^:]+):"))
            .Select(match => match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value);
        Assert.All(headers.Concat(values), value => Assert.DoesNotContain(value, outcome.FailureDetail));
    }

    // CONTRACT.agent-identity.md §6 step 6 accepts each (keyid, nonce) pair once, and the shared intent keeps each
    // accepted nonce until 60 s after its signature expires, the last instant at which step 3 accepts the signature.
    // The store call follows the last check of the window and may discard the pair once retainUntil has passed,
    // so a copy of the signature accepted at that instant reaches the store after it, and the pair must outlive it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Request authentication
    [Theory]
    [MemberData(nameof(OkCaseNames))]
    public async Task OkCaseRecordsItsNonceOnceUntilAfterItsWindowCloses(string name)
    {
        HttpSignatureCaseVector vector = Vectors.Case(name);
        VectorAuthority authority = new();

        await authority.RunAsync(vector);

        string signatureInput = vector.Headers.SignatureInput!;
        long expires = long.Parse(Parameter(signatureInput, "expires"), CultureInfo.InvariantCulture);
        DateTimeOffset windowEnd = DateTimeOffset.FromUnixTimeSeconds(expires + 60);
        (string KeyId, string Nonce, DateTimeOffset RetainUntil) call = Assert.Single(authority.Nonces.Calls);
        Assert.Equal(Parameter(signatureInput, "keyid"), call.KeyId);
        Assert.Equal(Parameter(signatureInput, "nonce"), call.Nonce);
        // oracle: mutant a retainUntil whose margin past the window's end is not 60 s, such as one tick
        Assert.Equal(windowEnd.AddSeconds(60), call.RetainUntil);
    }

    // Code that acts for an identity relies on these facts,
    // such as the status that tells confirm whether to promote the certificate.
    // The registered certificates of the vector file state them, in Unix seconds, independently of any time zone.
    // oracle: reference docs/agent-identity/test-vectors.json http_signature.registered
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    [Theory]
    [MemberData(nameof(OkSignedRequestCaseNames))]
    public async Task OkCaseIdentityIsThatOfTheSigningCertificate(string name)
    {
        HttpSignatureCaseVector vector = Vectors.Case(name);
        string keyId = Parameter(vector.Headers.SignatureInput!, "keyid");
        RegisteredCertificateVector registered = Vectors.Registered.Single(r => r.KeyId == keyId);
        VectorAuthority authority = new();
        authority.Clock.Now = vector.Now;
        SignedHttpRequest request = new(
            vector.Method,
            VectorAuthority.Lines(vector.Headers.SignatureInput),
            VectorAuthority.Lines(vector.Headers.Signature),
            VectorAuthority.Lines(vector.Headers.ContentDigest),
            vector.BodyBytes);

        AuthenticationResult result = await authority.Authenticator.AuthenticateAsync(
            VectorAuthority.Operation(vector.Endpoint),
            request);

        Assert.True(result.Succeeded);
        AuthenticatedIdentity identity = result.Identity;
        Assert.Equal(registered.IdentityId, identity.IdentityId);
        Assert.Equal(registered.KeyId, identity.CertificateThumbprint);
        Assert.Equal(registered.CertificateStatus, identity.CertificateStatus.ToString().ToLowerInvariant());
        Assert.Equal(registered.NotBefore, identity.CertificateNotBefore);
        Assert.Equal(registered.NotAfter, identity.CertificateNotAfter);
        // A renewal acts only for an identity that a renew request proved, so the identity carries its operation.
        // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
        Assert.Equal(VectorAuthority.Operation(vector.Endpoint), identity.Operation);
    }

    // A parameter value, quoted or not, read from the header text by this test rather than by the library.
    private static string Parameter(string signatureInput, string name)
    {
        return Regex.Match(signatureInput, $";{name}=\"?([^\";]+)").Groups[1].Value;
    }
}
