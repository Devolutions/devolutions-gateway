namespace Devolutions.AgentIdentity.Tests;

public class EnrollmentRulesTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    private static readonly Guid IdentityId = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    public static TheoryData<string> KeysButTheReplayNames => new(KeysButTheReplay.Keys);

    // The issued keys that each key rule of CONTRACT.md §2.1 matches, except the replay, by name.
    private static Dictionary<string, IssuedKeyMatch> KeysButTheReplay => new()
    {
        ["the key of another token's identity"] =
            IssuedKeyMatch.ForIdentity(IdentityId, false, false, CertificateStatus.Current),
        ["a key of a revoked identity"] = IssuedKeyMatch.ForIdentity(IdentityId, true, true, CertificateStatus.Current),
        ["the key of a pending certificate"] =
            IssuedKeyMatch.ForIdentity(IdentityId, true, false, CertificateStatus.Pending),
        ["the key of a retired certificate"] =
            IssuedKeyMatch.ForIdentity(IdentityId, true, false, CertificateStatus.Retired),
        ["the key of a deleted identity"] = IssuedKeyMatch.ForDeletedIdentity(),
    };

    // CONTRACT.md §2.1: a token creates an identity when it exists, has not been deleted, has not expired,
    // and fewer than `max_uses` identities have been created with it; (6) a new identity.
    // The rows are a usable token, one that expires one tick after now, and one that can create one more identity.
    [Theory]
    [InlineData(TimeSpan.TicksPerDay, 3)]
    [InlineData(1L, 3)]
    [InlineData(TimeSpan.TicksPerDay, 9)]
    public void CreatesAnIdentityForANewKeyWithAUsableToken(long ticksToExpiry, int identitiesCreated)
    {
        EnrollmentTokenState token = new(false, Now.AddTicks(ticksToExpiry), maxUses: 10, identitiesCreated);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, null, Now);

        Assert.Equal(EnrollmentOutcome.CreateIdentity, decision.Outcome);
        Assert.Null(decision.ExistingIdentityId);
        Assert.Null(decision.Error);
    }

    // CONTRACT.md §2.1: when several outcomes apply, the earliest wins:
    // (4) `token_invalid` for a deleted token, then `token_expired` for an expired one; (5) `token_exhausted`.
    [Theory]
    // CONTRACT.md §5.4: `token_expired` when `now ≥ expires_at`.
    [InlineData(false, 0L, 10, 3, AgentIdentityErrorCode.TokenExpired)]
    // CONTRACT.md §2.1: a token creates an identity only while fewer than `max_uses` identities have been created
    // with it.
    [InlineData(false, TimeSpan.TicksPerDay, 10, 10, AgentIdentityErrorCode.TokenExhausted)]
    [InlineData(false, TimeSpan.TicksPerDay, 10, 11, AgentIdentityErrorCode.TokenExhausted)]
    [InlineData(false, TimeSpan.TicksPerDay, 0, 0, AgentIdentityErrorCode.TokenExhausted)]
    // CONTRACT.md §2.1: a deleted token authenticates only for an idempotent replay;
    // every other use returns `token_invalid`, whether or not the token has also expired or been exhausted.
    [InlineData(true, TimeSpan.TicksPerDay, 10, 3, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, 0L, 10, 3, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, TimeSpan.TicksPerDay, 10, 10, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, 0L, 10, 10, AgentIdentityErrorCode.TokenInvalid)]
    // CONTRACT.md §2.1: (4) `token_expired` comes before (5) `token_exhausted`.
    [InlineData(false, 0L, 10, 10, AgentIdentityErrorCode.TokenExpired)]
    public void RejectsANewKeyWithTheEarliestTokenOutcome(
        bool deleted,
        long ticksToExpiry,
        int maxUses,
        int identitiesCreated,
        AgentIdentityErrorCode expected)
    {
        EnrollmentTokenState token = new(deleted, Now.AddTicks(ticksToExpiry), maxUses, identitiesCreated);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, null, Now);

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
    [InlineData(false, false, CertificateStatus.Current, false, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, false, CertificateStatus.Pending, false, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, false, CertificateStatus.Retired, false, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, true, CertificateStatus.Current, false, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(true, true, CertificateStatus.Current, false, false, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, true, CertificateStatus.Pending, false, false, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, true, CertificateStatus.Retired, false, false, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, false, CertificateStatus.Pending, false, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(true, false, CertificateStatus.Retired, false, false, AgentIdentityErrorCode.InvalidRequest)]
    // CONTRACT.md §2.1: (3) the result of the key lookup comes before (4) `token_expired` and (5) `token_exhausted`.
    [InlineData(false, false, CertificateStatus.Current, true, false, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(false, false, CertificateStatus.Current, false, true, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(true, true, CertificateStatus.Current, true, false, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, true, CertificateStatus.Retired, false, true, AgentIdentityErrorCode.IdentityRevoked)]
    [InlineData(true, false, CertificateStatus.Pending, true, true, AgentIdentityErrorCode.InvalidRequest)]
    public void RejectsAnIssuedKeyByTheFirstMatchingRule(
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

    // CONTRACT.md §2.1: the key of a certificate of a deleted identity → `identity_revoked`,
    // and (3) the result of the key lookup comes before (4) `token_expired` and (5) `token_exhausted`.
    // The authority keeps only the SPKI SHA-256 and issuance time of a deleted identity's keys,
    // so no other key rule applies to them.
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void RejectsTheKeyOfADeletedIdentityWithIdentityRevoked(bool expired, bool exhausted)
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(
            Token(expired: expired, exhausted: exhausted),
            IssuedKeyMatch.ForDeletedIdentity(),
            Now);

        AssertRejected(AgentIdentityErrorCode.IdentityRevoked, decision);
    }

    // CONTRACT.md §2.1 (3): a deleted token gets `token_invalid` for anything but an idempotent replay,
    // whatever the CSR public key matches.
    [Theory]
    [MemberData(nameof(KeysButTheReplayNames))]
    public void RejectsADeletedTokenWithTokenInvalidForAnIssuedKeyButTheReplay(string key)
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(deleted: true), KeysButTheReplay[key], Now);

        AssertRejected(AgentIdentityErrorCode.TokenInvalid, decision);
    }

    // Framework Design Guidelines: a bad argument throws the most derived ArgumentException, whose ParamName names it,
    // here ArgumentOutOfRangeException for a count below zero.
    [Theory]
    [InlineData(-1, 0, "maxUses")]
    [InlineData(1, -1, "identitiesCreated")]
    public void TokenStateRejectsANegativeCount(int maxUses, int identitiesCreated, string parameter)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => new EnrollmentTokenState(false, Now, maxUses, identitiesCreated));

        Assert.Equal(parameter, exception.ParamName);
    }

    // Statuses start at 1, so a status that the host never set is not a valid one,
    // and a value after the last status is not one either.
    // Framework Design Guidelines: validate enum arguments, and throw the most derived ArgumentException naming them.
    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void KeyMatchRejectsAnUndefinedCertificateStatus(int status)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => IssuedKeyMatch.ForIdentity(IdentityId, true, false, (CertificateStatus)status));

        Assert.Equal("status", exception.ParamName);
    }

    // Framework Design Guidelines: a null argument throws ArgumentNullException, whose ParamName names it.
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
