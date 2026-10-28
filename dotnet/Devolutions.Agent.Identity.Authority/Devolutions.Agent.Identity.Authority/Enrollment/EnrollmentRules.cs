namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Applies the enrollment rules that every authority shares to an enroll request.
/// </summary>
public static class EnrollmentRules
{
    /// <summary>
    /// Decides whether an enroll request creates an identity, replays the enrollment of an existing one,
    /// or is refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host calls this once <see cref="EnrollmentAuthorization.ReadBearerToken"/> and its token lookup succeed
    /// and the request body, CSR and metadata are valid.
    /// When several outcomes apply, the earliest of these wins:
    /// <c>token_url_mismatch</c> when the CSR names no enrollment URL, or not the token's <c>u</c>
    /// without trailing slashes, compared as text;
    /// the result of the CSR key lookup,
    /// except that a revoked token gets <c>token_invalid</c> for anything but a replay;
    /// <c>token_invalid</c> for a revoked token,
    /// then <c>token_expired</c> once <paramref name="now"/> reaches its expiry;
    /// <c>token_exhausted</c> once it has created <see cref="EnrollmentTokenState.MaxUses"/> identities;
    /// a new identity, whose ID, <see cref="EnrollmentDecision.NewIdentityId"/>, is minted at random for this decision,
    /// whose certificates name <see cref="EnrollmentDecision.EnrollmentUrl"/>,
    /// and whose certificate holds the CSR key, <see cref="EnrollmentDecision.SubjectPublicKeyInfoSha256"/>.
    /// </para>
    /// <para>
    /// The CSR key lookup takes the first matching rule:
    /// the current key of a non-revoked identity enrolled with the presented token replays that identity's enrollment;
    /// the key of an identity enrolled with another token gets <c>invalid_request</c>;
    /// any key of a revoked identity gets <c>identity_revoked</c>;
    /// a pending or retired key of a non-revoked identity gets <c>invalid_request</c>;
    /// the key of a deleted identity gets <c>identity_revoked</c>.
    /// </para>
    /// <para>
    /// The decision holds only for the state it was made from.
    /// The host creates the identity, inserts its key under a unique index of every issued key,
    /// and counts the use only while the stored count is still below <see cref="EnrollmentTokenState.MaxUses"/>,
    /// or, stricter, still equals <see cref="EnrollmentDecision.ExpectedIdentitiesCreated"/>, in one transaction,
    /// and decides again from the stored state when the count or the index refuses it, acting on the new decision,
    /// so that concurrent enrollments never create more than <see cref="EnrollmentTokenState.MaxUses"/> identities
    /// with one token, and of two concurrent enrollments with one CSR key, exactly one creates the identity
    /// and the other gets the replay.
    /// </para>
    /// </remarks>
    /// <param name="token">The state of the token that the request presents.</param>
    /// <param name="csr">The request's validated CSR.</param>
    /// <param name="keyMatch">The issued certificate whose public key is the CSR key, or null when none has it.</param>
    /// <param name="now">The authority's current time, read once for the request.</param>
    /// <exception cref="ArgumentNullException"><paramref name="token"/> or <paramref name="csr"/> is null.</exception>
    public static EnrollmentDecision Decide(
        EnrollmentTokenState token,
        CertificateSigningRequest csr,
        IssuedKeyMatch? keyMatch,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(csr);

        // CONTRACT.agent-identity.md §2.1 (2) and §4: a token works only at the base URL it names.
        string enrollmentUrl = token.ProductBaseUrl.TrimEnd('/');
        if (!string.Equals(csr.EnrollmentUrl, enrollmentUrl, StringComparison.Ordinal))
        {
            return EnrollmentDecision.Reject(
                AgentIdentityErrorCode.TokenUrlMismatch,
                "The CSR names no enrollment URL, or not the token's.");
        }

        if (keyMatch is not null)
        {
            if (keyMatch.IsReplay)
            {
                return EnrollmentDecision.ReturnExistingIdentity(keyMatch.IdentityId);
            }

            if (token.Revoked)
            {
                return EnrollmentDecision.Reject(
                    AgentIdentityErrorCode.TokenInvalid,
                    "The token is revoked, and the CSR key is not the current key of an identity that it created.");
            }

            return RejectIssuedKey(keyMatch);
        }

        if (token.Revoked)
        {
            return EnrollmentDecision.Reject(AgentIdentityErrorCode.TokenInvalid, "The token is revoked.");
        }

        if (!(now < token.ExpiresAt))
        {
            return EnrollmentDecision.Reject(AgentIdentityErrorCode.TokenExpired, "The token has expired.");
        }

        if (!(token.IdentitiesCreated < token.MaxUses))
        {
            return EnrollmentDecision.Reject(
                AgentIdentityErrorCode.TokenExhausted,
                "The token has created its maximum number of identities.");
        }

        return EnrollmentDecision.CreateIdentity(
            Guid.NewGuid(),
            enrollmentUrl,
            token.IdentitiesCreated,
            csr.SubjectPublicKeyInfoSha256);
    }

    // The key rules after the replay, in their order; a deleted identity matches only its own rule.
    private static EnrollmentDecision RejectIssuedKey(IssuedKeyMatch keyMatch)
    {
        if (keyMatch.IdentityDeleted)
        {
            return EnrollmentDecision.Reject(
                AgentIdentityErrorCode.IdentityRevoked,
                "The CSR key belongs to a deleted identity.");
        }

        if (!keyMatch.EnrolledWithPresentedToken)
        {
            return EnrollmentDecision.Reject(
                AgentIdentityErrorCode.InvalidRequest,
                "The CSR key belongs to an identity enrolled with another token.");
        }

        if (keyMatch.IdentityRevoked)
        {
            return EnrollmentDecision.Reject(
                AgentIdentityErrorCode.IdentityRevoked,
                "The CSR key belongs to a revoked identity.");
        }

        return EnrollmentDecision.Reject(
            AgentIdentityErrorCode.InvalidRequest,
            "The CSR key belongs to a pending or retired certificate.");
    }
}
