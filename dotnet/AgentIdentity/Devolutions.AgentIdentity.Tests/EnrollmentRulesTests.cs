namespace Devolutions.AgentIdentity.Tests;

public class EnrollmentRulesTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    private static readonly Guid IdentityId = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    // CONTRACT.md §2.1: a token creates an identity when it exists, has not been deleted, has not expired,
    // and fewer than `max_uses` identities have been created with it; (6) a new identity.
    [Fact]
    public void CreatesAnIdentityForANewKeyWithAUsableToken()
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(), null, Now);

        Assert.Equal(EnrollmentOutcome.CreateIdentity, decision.Outcome);
        Assert.Null(decision.ExistingIdentityId);
        Assert.Null(decision.Error);
    }

    // CONTRACT.md §5.4: `token_expired` when `now ≥ expires_at`.
    [Fact]
    public void RejectsATokenAtItsExpiryWithTokenExpired()
    {
        EnrollmentTokenState token = new(false, expiresAt: Now, maxUses: 10, identitiesCreated: 3);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, null, Now);

        AssertRejected(AgentIdentityErrorCode.TokenExpired, decision);
    }

    [Fact]
    public void CreatesAnIdentityJustBeforeTheTokenExpiry()
    {
        EnrollmentTokenState token = new(false, expiresAt: Now.AddTicks(1), maxUses: 10, identitiesCreated: 3);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, null, Now);

        Assert.Equal(EnrollmentOutcome.CreateIdentity, decision.Outcome);
    }

    // CONTRACT.md §2.1: a token creates an identity only while fewer than `max_uses` identities have been created
    // with it; (5) `token_exhausted`.
    [Theory]
    [InlineData(10, 10)]
    [InlineData(10, 11)]
    [InlineData(0, 0)]
    public void RejectsATokenThatCreatedMaxUsesIdentitiesWithTokenExhausted(int maxUses, int identitiesCreated)
    {
        EnrollmentTokenState token = new(false, Now.AddDays(1), maxUses, identitiesCreated);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, null, Now);

        AssertRejected(AgentIdentityErrorCode.TokenExhausted, decision);
    }

    [Fact]
    public void CreatesTheLastIdentityThatATokenAllows()
    {
        EnrollmentTokenState token = new(false, Now.AddDays(1), maxUses: 10, identitiesCreated: 9);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, null, Now);

        Assert.Equal(EnrollmentOutcome.CreateIdentity, decision.Outcome);
    }

    // CONTRACT.md §2.1: a deleted token authenticates only for an idempotent replay;
    // every other use returns `token_invalid`.
    [Fact]
    public void RejectsADeletedTokenWithTokenInvalid()
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(deleted: true), null, Now);

        AssertRejected(AgentIdentityErrorCode.TokenInvalid, decision);
    }

    // CONTRACT.md §2.1: when several outcomes apply, the earliest wins:
    // (4) `token_invalid` for a deleted token, then `token_expired` for an expired one; (5) `token_exhausted`.
    [Theory]
    [InlineData(true, true, false, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, false, true, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, true, true, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(false, true, true, AgentIdentityErrorCode.TokenExpired)]
    public void RejectsANewKeyWithTheEarliestTokenOutcome(
        bool deleted,
        bool expired,
        bool exhausted,
        AgentIdentityErrorCode expected)
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(deleted, expired, exhausted), null, Now);

        AssertRejected(expected, decision);
    }

    // CONTRACT.md §2.1: the key of the current certificate of a non-revoked identity enrolled with the same token
    // → 200 with that identity, without counting a use.
    // The key lookup (3) comes before (4) and (5), and a deleted token authenticates for this replay,
    // so the replay wins whether the token is deleted, expired or exhausted.
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    [InlineData(true, true, true)]
    public void ReturnsTheIdentityOfAReplayedKeyWhateverTheTokenState(bool deleted, bool expired, bool exhausted)
    {
        IssuedKeyMatch keyMatch = IssuedKeyMatch.ForIdentity(IdentityId, true, false, CertificateStatus.Current);

        EnrollmentDecision decision = EnrollmentRules.Decide(Token(deleted, expired, exhausted), keyMatch, Now);

        Assert.Equal(EnrollmentOutcome.ReturnExistingIdentity, decision.Outcome);
        Assert.Equal(IdentityId, decision.ExistingIdentityId);
        Assert.Null(decision.Error);
    }

    // CONTRACT.md §2.1: the first matching key rule decides.
    // The key of an identity enrolled with a different token → `invalid_request`, before the revocation rule;
    // any certificate key of a revoked identity → `identity_revoked`, before the pending-or-retired rule
    // and instead of the replay, which needs a non-revoked identity;
    // the key of a pending or retired certificate of a non-revoked identity → `invalid_request`,
    // instead of the replay, which needs the current certificate.
    [Theory]
    [InlineData(false, false, CertificateStatus.Current, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, false, CertificateStatus.Pending, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, false, CertificateStatus.Retired, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, true, CertificateStatus.Current, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(true, true, CertificateStatus.Current, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, true, CertificateStatus.Pending, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, true, CertificateStatus.Retired, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, false, CertificateStatus.Pending, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(true, false, CertificateStatus.Retired, AgentIdentityErrorCode.InvalidRequest)]
    public void RejectsAnIssuedKeyByTheFirstMatchingRule(
        bool enrolledWithPresentedToken,
        bool identityRevoked,
        CertificateStatus status,
        AgentIdentityErrorCode expected)
    {
        IssuedKeyMatch keyMatch =
            IssuedKeyMatch.ForIdentity(IdentityId, enrolledWithPresentedToken, identityRevoked, status);

        EnrollmentDecision decision = EnrollmentRules.Decide(Token(), keyMatch, Now);

        AssertRejected(expected, decision);
    }

    // CONTRACT.md §2.1: the key of a certificate of a deleted identity → `identity_revoked`.
    // The authority keeps only the SPKI SHA-256 and issuance time of a deleted identity's keys,
    // so no other key rule applies to them.
    [Fact]
    public void RejectsTheKeyOfADeletedIdentityWithIdentityRevoked()
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(), IssuedKeyMatch.ForDeletedIdentity(), Now);

        AssertRejected(AgentIdentityErrorCode.IdentityRevoked, decision);
    }

    // CONTRACT.md §2.1: (3) the result of the key lookup comes before (4) `token_expired` and (5) `token_exhausted`.
    [Theory]
    [InlineData(false, false, CertificateStatus.Current, true, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, false, CertificateStatus.Current, false, true, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(true, true, CertificateStatus.Current, true, false, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, true, CertificateStatus.Retired, false, true, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, false, CertificateStatus.Pending, true, true, AgentIdentityErrorCode.InvalidRequest)]
    public void RejectsAnIssuedKeyBeforeAnExpiredOrExhaustedToken(
        bool enrolledWithPresentedToken,
        bool identityRevoked,
        CertificateStatus status,
        bool expired,
        bool exhausted,
        AgentIdentityErrorCode expected)
    {
        IssuedKeyMatch keyMatch =
            IssuedKeyMatch.ForIdentity(IdentityId, enrolledWithPresentedToken, identityRevoked, status);

        EnrollmentDecision decision =
            EnrollmentRules.Decide(Token(expired: expired, exhausted: exhausted), keyMatch, Now);

        AssertRejected(expected, decision);
    }

    [Fact]
    public void RejectsTheKeyOfADeletedIdentityBeforeAnExpiredAndExhaustedToken()
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(
            Token(expired: true, exhausted: true),
            IssuedKeyMatch.ForDeletedIdentity(),
            Now);

        AssertRejected(AgentIdentityErrorCode.IdentityRevoked, decision);
    }

    // CONTRACT.md §2.1 (3): a deleted token gets `token_invalid` for anything but an idempotent replay,
    // whatever the CSR public key matches.
    [Theory]
    [InlineData(false, false, CertificateStatus.Current)]
    [InlineData(true, true, CertificateStatus.Current)]
    [InlineData(true, false, CertificateStatus.Pending)]
    [InlineData(true, false, CertificateStatus.Retired)]
    public void RejectsADeletedTokenWithTokenInvalidForAnIssuedKeyButTheReplay(
        bool enrolledWithPresentedToken,
        bool identityRevoked,
        CertificateStatus status)
    {
        IssuedKeyMatch keyMatch =
            IssuedKeyMatch.ForIdentity(IdentityId, enrolledWithPresentedToken, identityRevoked, status);

        EnrollmentDecision decision = EnrollmentRules.Decide(Token(deleted: true), keyMatch, Now);

        AssertRejected(AgentIdentityErrorCode.TokenInvalid, decision);
    }

    [Fact]
    public void RejectsADeletedTokenWithTokenInvalidForTheKeyOfADeletedIdentity()
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(
            Token(deleted: true),
            IssuedKeyMatch.ForDeletedIdentity(),
            Now);

        AssertRejected(AgentIdentityErrorCode.TokenInvalid, decision);
    }

    [Theory]
    [InlineData(-1, 0, "maxUses")]
    [InlineData(1, -1, "identitiesCreated")]
    public void TokenStateRejectsANegativeCount(int maxUses, int identitiesCreated, string parameter)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => new EnrollmentTokenState(false, Now, maxUses, identitiesCreated));

        Assert.Equal(parameter, exception.ParamName);
    }

    [Fact]
    public void KeyMatchRejectsAnUndefinedCertificateStatus()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => IssuedKeyMatch.ForIdentity(IdentityId, true, false, (CertificateStatus)3));

        Assert.Equal("status", exception.ParamName);
    }

    [Fact]
    public void DecideRejectsANullToken()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentRules.Decide(null!, null, Now));

        Assert.Equal("token", exception.ParamName);
    }

    private static void AssertRejected(AgentIdentityErrorCode expected, EnrollmentDecision decision)
    {
        Assert.Equal(EnrollmentOutcome.Reject, decision.Outcome);
        Assert.Equal(expected, decision.Error?.Code);
        Assert.Null(decision.ExistingIdentityId);
        Assert.False(string.IsNullOrEmpty(decision.FailureDetail));
    }

    // A token that is neither deleted, expired nor exhausted, unless a flag says otherwise.
    private static EnrollmentTokenState Token(bool deleted = false, bool expired = false, bool exhausted = false)
    {
        return new EnrollmentTokenState(
            deleted,
            expiresAt: expired ? Now : Now.AddDays(1),
            maxUses: 10,
            identitiesCreated: exhausted ? 10 : 3);
    }
}
