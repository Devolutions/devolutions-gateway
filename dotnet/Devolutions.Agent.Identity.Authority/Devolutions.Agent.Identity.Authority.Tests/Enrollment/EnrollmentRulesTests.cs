namespace Devolutions.Agent.Identity.Authority.Tests;

public class EnrollmentRulesTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    private static readonly Guid IdentityId = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");

    // The `u` of the presented token, and the CSR an agent enrolling with it sends, which names that URL.
    private const string TokenUrl = "https://host/dvls";

    private static readonly CertificateSigningRequest Csr = TestEnrollmentUrl.Csr(TokenUrl);

    public static TheoryData<string> KeysButTheReplayNames => new(KeysButTheReplay.Keys);

    // The issued keys that each key rule of CONTRACT.agent-identity.md §2.1 matches, except the replay, by name.
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

    // A decision of each outcome but the creation of an identity: an expired token's refusal and a replay.
    private static Dictionary<EnrollmentOutcome, EnrollmentDecision> DecisionsButCreateIdentity => new()
    {
        [EnrollmentOutcome.Reject] = EnrollmentRules.Decide(Token(expired: true), Csr, null, Now),
        [EnrollmentOutcome.ReturnExistingIdentity] = EnrollmentRules.Decide(
            Token(),
            Csr,
            IssuedKeyMatch.ForIdentity(IdentityId, true, false, CertificateStatus.Current),
            Now),
    };

    // A token creates an identity when it exists, has not been revoked,
    // has not expired, and fewer than `max_uses` identities have been created with it; (6) a new identity.
    // The rows are a usable token, one that expires one tick after now, and one that can create one more identity.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [InlineData(TimeSpan.TicksPerDay, 3)]
    // `token_expired` only when `now ≥ expires_at`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(1L, 3)]
    [InlineData(TimeSpan.TicksPerDay, 9)]
    public void CreatesAnIdentityForANewKeyWithAUsableToken(long ticksToExpiry, int identitiesCreated)
    {
        EnrollmentTokenState token = new(false, TokenUrl, Now.AddTicks(ticksToExpiry), maxUses: 10, identitiesCreated);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, Csr, null, Now);

        Assert.Equal(EnrollmentOutcome.CreateIdentity, decision.Outcome);
        Assert.Null(decision.ExistingIdentityId);
        Assert.Null(decision.Error);
    }

    // Security invariant 2: the authority mints the identity's UUID,
    // so a decision to create an identity carries one, not the nil UUID that an unset Guid holds.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Fact]
    public void CreateIdentityCarriesAnIdentityId()
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(), Csr, null, Now);

        Guid identityId = Assert.NotNull(decision.NewIdentityId);
        Assert.NotEqual(Guid.Empty, identityId);
    }

    // Security invariant 2: the authority mints the identity's UUID, and an identity is never derived from the
    // enrollment token, so two identities that one token creates get different IDs.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Fact]
    public void EachCreateIdentityCarriesADifferentIdentityId()
    {
        EnrollmentDecision first = EnrollmentRules.Decide(Token(), Csr, null, Now);
        EnrollmentDecision second = EnrollmentRules.Decide(Token(), Csr, null, Now);

        Assert.NotEqual(first.NewIdentityId, second.NewIdentityId);
    }

    // A refusal creates no identity, and a replay returns the identity that the key already belongs to.
    [Theory]
    // oracle: mutant a refusal that carries a new identity ID
    [InlineData(EnrollmentOutcome.Reject)]
    // oracle: mutant a replay that carries a new identity ID
    [InlineData(EnrollmentOutcome.ReturnExistingIdentity)]
    public void CarriesNoNewIdentityIdWhenCreatingNone(EnrollmentOutcome outcome)
    {
        EnrollmentDecision decision = DecisionsButCreateIdentity[outcome];

        Assert.Null(decision.NewIdentityId);
    }

    // When several outcomes apply, the earliest wins:
    // (4) `token_invalid` for a revoked token, then `token_expired` for an expired one; (5) `token_exhausted`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    // `token_expired` when `now ≥ expires_at`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(false, 0L, 10, 3, AgentIdentityErrorCode.TokenExpired)]
    // A token creates an identity only while fewer than `max_uses` identities have been created with it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [InlineData(false, TimeSpan.TicksPerDay, 10, 10, AgentIdentityErrorCode.TokenExhausted)]
    [InlineData(false, TimeSpan.TicksPerDay, 10, 11, AgentIdentityErrorCode.TokenExhausted)]
    [InlineData(false, TimeSpan.TicksPerDay, 0, 0, AgentIdentityErrorCode.TokenExhausted)]
    // A revoked token authenticates only for an idempotent replay;
    // every other use returns `token_invalid`, whether or not the token has also expired or been exhausted.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [InlineData(true, TimeSpan.TicksPerDay, 10, 3, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, 0L, 10, 3, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, TimeSpan.TicksPerDay, 10, 10, AgentIdentityErrorCode.TokenInvalid)]
    [InlineData(true, 0L, 10, 10, AgentIdentityErrorCode.TokenInvalid)]
    // (4) `token_expired` comes before (5) `token_exhausted`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [InlineData(false, 0L, 10, 10, AgentIdentityErrorCode.TokenExpired)]
    public void RejectsANewKeyWithTheEarliestTokenOutcome(
        bool revoked,
        long ticksToExpiry,
        int maxUses,
        int identitiesCreated,
        AgentIdentityErrorCode expected)
    {
        EnrollmentTokenState token = new(revoked, TokenUrl, Now.AddTicks(ticksToExpiry), maxUses, identitiesCreated);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, Csr, null, Now);

        AssertRejected(expected, decision);
    }

    // The key of the current certificate of a non-revoked identity enrolled with the
    // same token → 200 with that identity, without counting a use.
    // The key lookup (3) comes before (4) and (5), and a revoked token authenticates for this replay,
    // so the replay wins whether the token is revoked, expired or exhausted.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    [InlineData(true, true, true)]
    public void ReturnsTheIdentityOfAReplayedKeyWhateverTheTokenState(bool revoked, bool expired, bool exhausted)
    {
        IssuedKeyMatch keyMatch = IssuedKeyMatch.ForIdentity(IdentityId, true, false, CertificateStatus.Current);

        EnrollmentDecision decision = EnrollmentRules.Decide(Token(revoked, expired, exhausted), Csr, keyMatch, Now);

        Assert.Equal(EnrollmentOutcome.ReturnExistingIdentity, decision.Outcome);
        Assert.Equal(IdentityId, decision.ExistingIdentityId);
        Assert.Null(decision.Error);
    }

    // The first matching key rule decides.
    // The key of an identity enrolled with a different token → `invalid_request`, before the revocation rule;
    // any certificate key of a revoked identity → `identity_revoked`, before the pending-or-retired rule
    // and instead of the replay, which needs a non-revoked identity;
    // the key of a pending or retired certificate of a non-revoked identity → `invalid_request`,
    // instead of the replay, which needs the current certificate.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
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
    // (3) the result of the key lookup comes before (4) `token_expired` and (5) `token_exhausted`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
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
            EnrollmentRules.Decide(Token(expired: expired, exhausted: exhausted), Csr, keyMatch, Now);

        AssertRejected(expected, decision);
    }

    // The key of a certificate of a deleted identity → `identity_revoked`,
    // and (3) the result of the key lookup comes before (4) `token_expired` and (5) `token_exhausted`.
    // The authority keeps only the SPKI SHA-256 and issuance time of a deleted identity's keys,
    // so no other key rule applies to them.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void RejectsTheKeyOfADeletedIdentityWithIdentityRevoked(bool expired, bool exhausted)
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(
            Token(expired: expired, exhausted: exhausted),
            Csr,
            IssuedKeyMatch.ForDeletedIdentity(),
            Now);

        AssertRejected(AgentIdentityErrorCode.IdentityRevoked, decision);
    }

    // (3): a revoked token gets `token_invalid` for anything but an idempotent replay,
    // whatever the CSR public key matches.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [MemberData(nameof(KeysButTheReplayNames))]
    public void RejectsARevokedTokenWithTokenInvalidForAnIssuedKeyButTheReplay(string key)
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(revoked: true), Csr, KeysButTheReplay[key], Now);

        AssertRejected(AgentIdentityErrorCode.TokenInvalid, decision);
    }

    // At enrollment, a CSR that lacks the enrollment URL extension, or whose value is not the presented token's `u`
    // without trailing slashes, gets token_url_mismatch, compared as text.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [MemberData(nameof(CsrsNotNamingTheTokenUrlNames))]
    public void RejectsACsrNotNamingTheTokenUrlWithTokenUrlMismatch(string csr)
    {
        EnrollmentDecision decision = EnrollmentRules.Decide(Token(), CsrsNotNamingTheTokenUrl[csr](), null, Now);

        AssertRejected(AgentIdentityErrorCode.TokenUrlMismatch, decision);
    }

    public static TheoryData<string> CsrsNotNamingTheTokenUrlNames => new(CsrsNotNamingTheTokenUrl.Keys);

    // CSRs whose enrollment URL is not https://host/dvls, by what they name.
    private static Dictionary<string, Func<CertificateSigningRequest>> CsrsNotNamingTheTokenUrl => new()
    {
        ["no enrollment URL"] = TestEnrollmentUrl.CsrWithoutEnrollmentUrl,
        ["another path"] = () => TestEnrollmentUrl.Csr("https://host/psu"),
        ["another host"] = () => TestEnrollmentUrl.Csr("https://other/dvls"),
        // Compared as text, a trailing slash, an uppercase host and a port make another value.
        ["a trailing slash"] = () => TestEnrollmentUrl.Csr("https://host/dvls/"),
        ["an uppercase host"] = () => TestEnrollmentUrl.Csr("https://HOST/dvls"),
        ["the default port"] = () => TestEnrollmentUrl.Csr("https://host:443/dvls"),
    };

    // (2) `token_url_mismatch` follows `invalid_request` and comes before (3) the key lookup,
    // (4) `token_invalid` for a revoked token and `token_expired`, and (5) `token_exhausted`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [MemberData(nameof(LaterOutcomeNames))]
    public void TokenUrlMismatchWinsOverTheLaterOutcomes(string laterOutcome)
    {
        (EnrollmentTokenState token, IssuedKeyMatch? keyMatch) = LaterOutcomes[laterOutcome];

        EnrollmentDecision decision =
            EnrollmentRules.Decide(token, TestEnrollmentUrl.Csr("https://host/psu"), keyMatch, Now);

        AssertRejected(AgentIdentityErrorCode.TokenUrlMismatch, decision);
    }

    public static TheoryData<string> LaterOutcomeNames => new(LaterOutcomes.Keys);

    // Token states and key matches that a CSR naming the token's URL would get, by that outcome.
    private static Dictionary<string, (EnrollmentTokenState Token, IssuedKeyMatch? KeyMatch)> LaterOutcomes => new()
    {
        ["a new identity"] = (Token(), null),
        ["the replay of an identity"] = (
            Token(revoked: true, expired: true, exhausted: true),
            IssuedKeyMatch.ForIdentity(IdentityId, true, false, CertificateStatus.Current)),
        ["the key of a revoked identity"] =
            (Token(), IssuedKeyMatch.ForIdentity(IdentityId, true, true, CertificateStatus.Current)),
        ["a revoked token"] = (Token(revoked: true), null),
        ["an expired token"] = (Token(expired: true), null),
        ["an exhausted token"] = (Token(exhausted: true), null),
    };

    // The CSR names the token's `u` without trailing slashes, whatever trailing slashes the stored `u` has,
    // and the decision to create an identity carries that URL, which every certificate of the identity names.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Theory]
    [InlineData("https://host/dvls")]
    [InlineData("https://host/dvls/")]
    [InlineData("https://host/dvls//")]
    public void CreateIdentityCarriesTheTokenUrlWithoutTrailingSlashes(string storedUrl)
    {
        EnrollmentTokenState token = new(false, storedUrl, Now.AddDays(1), maxUses: 10, identitiesCreated: 3);

        EnrollmentDecision decision = EnrollmentRules.Decide(token, Csr, null, Now);

        Assert.Equal(EnrollmentOutcome.CreateIdentity, decision.Outcome);
        Assert.Equal(TokenUrl, decision.EnrollmentUrl);
    }

    // Only the decision to create an identity issues a certificate.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
    [Theory]
    [InlineData(EnrollmentOutcome.Reject)]
    [InlineData(EnrollmentOutcome.ReturnExistingIdentity)]
    public void OtherDecisionsCarryNoEnrollmentUrl(EnrollmentOutcome outcome)
    {
        Assert.Null(DecisionsButCreateIdentity[outcome].EnrollmentUrl);
    }

    // A bad argument throws the most derived ArgumentException, whose ParamName names it,
    // here ArgumentOutOfRangeException for a count below zero.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Theory]
    [InlineData(-1, 0, "maxUses")]
    [InlineData(1, -1, "identitiesCreated")]
    public void TokenStateRejectsANegativeCount(int maxUses, int identitiesCreated, string parameter)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => new EnrollmentTokenState(false, TokenUrl, Now, maxUses, identitiesCreated));

        Assert.Equal(parameter, exception.ParamName);
    }

    // The token's `u` is an absolute https URL (CONTRACT.agent-identity.md §2), so none is empty once its trailing
    // slashes are removed, and the CSR's enrollment URL is compared with it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData("")]
    [InlineData("/")]
    public void TokenStateRejectsAnEmptyProductBaseUrl(string productBaseUrl)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => new EnrollmentTokenState(false, productBaseUrl, Now, maxUses: 10, identitiesCreated: 0));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void TokenStateRejectsANullProductBaseUrl()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => new EnrollmentTokenState(false, null!, Now, maxUses: 10, identitiesCreated: 0));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    // Statuses start at 1, so a status that the host never set is not a valid one,
    // and a value after the last status is not one either.
    // Framework Design Guidelines: validate enum arguments, and throw the most derived ArgumentException naming them.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §definitions
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void KeyMatchRejectsAnUndefinedCertificateStatus(int status)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => IssuedKeyMatch.ForIdentity(IdentityId, true, false, (CertificateStatus)status));

        Assert.Equal("status", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void DecideRejectsANullToken()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentRules.Decide(null!, Csr, null, Now));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("token", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void DecideRejectsANullCsr()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentRules.Decide(Token(), null!, null, Now));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("csr", exception.ParamName);
    }

    private static void AssertRejected(AgentIdentityErrorCode expected, EnrollmentDecision decision)
    {
        Assert.Equal(EnrollmentOutcome.Reject, decision.Outcome);
        Assert.Equal(expected, decision.Error?.Code);
        Assert.Null(decision.ExistingIdentityId);
        // oracle: mutant an empty failure detail for an enrollment refused for a revoked, expired or exhausted token,
        // or for a CSR key of a deleted, revoked or other-token identity or of a pending or retired certificate
        Assert.False(string.IsNullOrEmpty(decision.FailureDetail));
    }

    // A token that is neither revoked, expired nor exhausted, unless a flag says otherwise.
    private static EnrollmentTokenState Token(bool revoked = false, bool expired = false, bool exhausted = false)
    {
        return new EnrollmentTokenState(
            revoked,
            TokenUrl,
            expiresAt: expired ? Now : Now.AddDays(1),
            maxUses: 10,
            identitiesCreated: exhausted ? 10 : 3);
    }
}
