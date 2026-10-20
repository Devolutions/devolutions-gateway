namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The CSR key rules of a renew request, CONTRACT.md §5.3.
/// </summary>
/// <remarks>
/// Every request is a renew request that device-a signed; device-b of the vector file is another identity.
/// </remarks>
public class RenewalRulesTests
{
    private static readonly Guid OtherIdentityId = TestVectors.Instance.Key("device-b").IdentityId;

    // CONTRACT.md §5.3: the key of any other certificate that the server has issued, including this identity's
    // current or retired certificates and every certificate of another identity, gets invalid_request.
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

    // CONTRACT.md §5.3: if the CSR key is the key of the identity's pending certificate,
    // the server returns 200 with that pending chain, a retry after a lost response.
    // A renew request presents no enrollment token, so whatever the host says about one does not count.
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

        RenewalDecision decision = RenewalRules.Decide(renewing, keyMatch);

        Assert.Equal(RenewalOutcome.ReturnPendingCertificate, decision.Outcome);
        Assert.Null(decision.Error);
        Assert.Null(decision.FailureDetail);
    }

    [Theory]
    [MemberData(nameof(OtherIssuedKeyNames))]
    public async Task RejectsAnyOtherIssuedKeyWithInvalidRequest(string key)
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        RenewalDecision decision = RenewalRules.Decide(renewing, OtherIssuedKeys[key](renewing.IdentityId));

        Assert.Equal(RenewalOutcome.Reject, decision.Outcome);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, decision.Error?.Code);
        Assert.Equal(400, decision.Error?.HttpStatusCode);
        Assert.False(string.IsNullOrEmpty(decision.FailureDetail));
    }

    // CONTRACT.md §5.3: if the CSR key was never issued, the server issues a new pending certificate
    // and retires the identity's previous pending certificate, if any.
    [Fact]
    public async Task IssuesAPendingCertificateForAKeyNeverIssued()
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        RenewalDecision decision = RenewalRules.Decide(renewing, null);

        Assert.Equal(RenewalOutcome.IssuePendingCertificate, decision.Outcome);
        Assert.Null(decision.Error);
        Assert.Null(decision.FailureDetail);
    }

    // INTENT.md: code that acts for an identity takes the identity that the signature check produced,
    // and only a renew request proves the identity that a renewal acts for.
    [Theory]
    [InlineData(AgentOperation.Confirm)]
    [InlineData(AgentOperation.CheckIn)]
    [InlineData(AgentOperation.Connect)]
    public async Task ThrowsForAnIdentityAuthenticatedForAnotherOperation(AgentOperation operation)
    {
        AuthenticatedIdentity identity = await TestIdentity.AuthenticateAsync(operation);

        ArgumentException exception = Assert.Throws<ArgumentException>(() => RenewalRules.Decide(identity, null));

        Assert.Equal("renewing", exception.ParamName);
    }

    [Fact]
    public void ThrowsForANullIdentity()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => RenewalRules.Decide(null!, null));

        Assert.Equal("renewing", exception.ParamName);
    }
}
