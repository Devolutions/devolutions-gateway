using System.Security.Cryptography;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// The CSR key rules of a renew request, CONTRACT.agent-identity.md §5.3.
/// </summary>
/// <remarks>
/// Every request is a renew request that device-a signed; device-b of the vector file is another identity.
/// </remarks>
public class RenewalRulesTests
{
    private static readonly Guid OtherIdentityId = TestVectors.Instance.Key("device-b").IdentityId;

    // The CSR of the renew request; a renewal ignores the enrollment URL it names (CONTRACT.agent-identity.md §4).
    private static readonly CertificateSigningRequest Csr = TestEnrollmentUrl.Csr("https://host/dvls");

    // CONTRACT.agent-identity.md §5.3: the key of any other certificate that the server has issued, including this
    // identity's current or retired certificates and every certificate of another identity, gets invalid_request.
    // A deleted identity's certificates are certificates that the server has issued.
    private static readonly Dictionary<string, Func<Guid, IssuedKeyMatch>> OtherIssuedKeys = new()
    {
        ["the current key of the identity"] = identityId =>
            IssuedKeyMatch.ForIdentity(identityId, false, false, CertificateStatus.Current),
        ["a retired key of the identity"] = identityId =>
            IssuedKeyMatch.ForIdentity(identityId, false, false, CertificateStatus.Retired),
        ["the pending key of another identity"] = _ =>
            IssuedKeyMatch.ForIdentity(OtherIdentityId, false, false, CertificateStatus.Pending),
        ["the current key of another identity"] = _ =>
            IssuedKeyMatch.ForIdentity(OtherIdentityId, false, false, CertificateStatus.Current),
        ["a retired key of another identity"] = _ =>
            IssuedKeyMatch.ForIdentity(OtherIdentityId, false, false, CertificateStatus.Retired),
        ["the pending key of another identity, which is revoked"] = _ =>
            IssuedKeyMatch.ForIdentity(OtherIdentityId, false, true, CertificateStatus.Pending),
        ["a key of a deleted identity"] = _ => IssuedKeyMatch.ForDeletedIdentity(),
    };

    public static TheoryData<string> OtherIssuedKeyNames => new(OtherIssuedKeys.Keys);

    // If the CSR key is the key of the identity's pending certificate,
    // the server returns 200 with that pending chain, a retry after a lost response.
    // A renew request presents no enrollment token, so whatever the host says about one does not count.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReturnsThePendingCertificateForThePendingKeyOfTheIdentity(bool enrolledWithPresentedToken)
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);
        IssuedKeyMatch keyMatch = IssuedKeyMatch.ForIdentity(
            renewing.IdentityId,
            enrolledWithPresentedToken,
            identityRevoked: false,
            CertificateStatus.Pending);

        RenewalDecision decision = RenewalRules.Decide(renewing, Csr, keyMatch);

        Assert.Equal(RenewalOutcome.ReturnPendingCertificate, decision.Outcome);
        Assert.Null(decision.Error);
        // oracle: mutant a decision to return the pending certificate that carries the key digest of a decision to issue
        Assert.True(decision.SubjectPublicKeyInfoSha256.IsEmpty);
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    [Theory]
    [MemberData(nameof(OtherIssuedKeyNames))]
    public async Task RejectsAnyOtherIssuedKeyWithInvalidRequest(string key)
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        RenewalDecision decision = RenewalRules.Decide(renewing, Csr, OtherIssuedKeys[key](renewing.IdentityId));

        Assert.Equal(RenewalOutcome.Reject, decision.Outcome);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, decision.Error?.Code);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        Assert.Equal(400, decision.Error?.HttpStatusCode);
        // oracle: mutant an empty failure detail for the CSR key of a deleted identity, of another identity,
        // or of a current or retired certificate of the renewing identity
        Assert.False(string.IsNullOrEmpty(decision.FailureDetail));
        // oracle: mutant a refusal that carries the key digest of a decision to issue
        Assert.True(decision.SubjectPublicKeyInfoSha256.IsEmpty);
    }

    // If the CSR key was never issued, the server issues a new pending certificate
    // and retires the identity's previous pending certificate, if any.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    [Fact]
    public async Task IssuesAPendingCertificateForAKeyNeverIssued()
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        RenewalDecision decision = RenewalRules.Decide(renewing, Csr, null);

        Assert.Equal(RenewalOutcome.IssuePendingCertificate, decision.Outcome);
        Assert.Null(decision.Error);
    }

    // Every issued public key is unique by SPKI SHA-256, the SHA-256 of the DER SubjectPublicKeyInfo,
    // so a decision to issue names the key it was made for by that digest, computed here from the key itself.
    // A decision naming another value would have the host index a key other than the one it certifies.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §definitions
    [Fact]
    public async Task IssuePendingCertificateCarriesTheSpkiSha256OfTheCsrKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateSigningRequest csr = TestEnrollmentUrl.Csr(key, "https://host/dvls");
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        RenewalDecision decision = RenewalRules.Decide(renewing, csr, null);

        Assert.Equal(SHA256.HashData(key.ExportSubjectPublicKeyInfo()), decision.SubjectPublicKeyInfoSha256.ToArray());
    }

    // Code that acts for an identity takes the identity that the signature check produced,
    // and only a renew request proves the identity that a renewal acts for.
    // An identity that proved its key for another operation never had a renew request accepted for it.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData(AgentOperation.Confirm)]
    [InlineData(AgentOperation.CheckIn)]
    [InlineData(AgentOperation.Connect)]
    public async Task ThrowsForAnIdentityAuthenticatedForAnotherOperation(AgentOperation operation)
    {
        AuthenticatedIdentity identity = await TestIdentity.AuthenticateAsync(operation);

        ArgumentException exception = Assert.Throws<ArgumentException>(() => RenewalRules.Decide(identity, Csr, null));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("renewing", exception.ParamName);
    }

    // INTENT.md: a renewal acts for the identity that a renew request proved, and null is no identity;
    // the .NET Framework Design Guidelines throw ArgumentNullException for a null argument that is not allowed.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void ThrowsForANullIdentity()
    {
        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(() => RenewalRules.Decide(null!, Csr, null));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("renewing", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public async Task ThrowsForANullCsr()
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(() => RenewalRules.Decide(renewing, null!, null));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("csr", exception.ParamName);
    }
}
