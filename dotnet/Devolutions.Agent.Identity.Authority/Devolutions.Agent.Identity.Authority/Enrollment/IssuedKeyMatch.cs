namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The issued certificate whose public key is the key of an enroll or renew request's CSR.
/// </summary>
/// <remarks>
/// The host finds it by the SPKI SHA-256 of the CSR key among every certificate the authority has issued:
/// current, pending and retired certificates, and those of deleted identities.
/// </remarks>
public sealed class IssuedKeyMatch
{
    private static readonly IssuedKeyMatch DeletedIdentity = new(Guid.Empty, true, false, false, default);

    private IssuedKeyMatch(
        Guid identityId,
        bool identityDeleted,
        bool enrolledWithPresentedToken,
        bool identityRevoked,
        CertificateStatus status)
    {
        IdentityId = identityId;
        IdentityDeleted = identityDeleted;
        EnrolledWithPresentedToken = enrolledWithPresentedToken;
        IdentityRevoked = identityRevoked;
        Status = status;
    }

    internal Guid IdentityId { get; }

    internal bool IdentityDeleted { get; }

    internal bool EnrolledWithPresentedToken { get; }

    internal bool IdentityRevoked { get; }

    internal CertificateStatus Status { get; }

    /// <summary>
    /// Whether the key is the current key of a non-revoked identity enrolled with the presented token,
    /// so that the request replays that identity's enrollment.
    /// </summary>
    internal bool IsReplay =>
        !IdentityDeleted && EnrolledWithPresentedToken && !IdentityRevoked && Status == CertificateStatus.Current;

    /// <summary>
    /// Creates the match of a certificate of an identity that the authority holds.
    /// </summary>
    /// <remarks>
    /// <see cref="RenewalRules.Decide"/> reads only the identity and the status,
    /// since a renewal refuses any key of another identity, revoked or not.
    /// </remarks>
    /// <param name="identityId">The identity that the certificate was issued to.</param>
    /// <param name="enrolledWithPresentedToken">
    /// Whether the identity was enrolled with the token that the request presents;
    /// false for a renew request, which presents none.
    /// </param>
    /// <param name="identityRevoked">Whether the identity is revoked.</param>
    /// <param name="status">The status of the certificate.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="status"/> is not a defined status.</exception>
    public static IssuedKeyMatch ForIdentity(
        Guid identityId,
        bool enrolledWithPresentedToken,
        bool identityRevoked,
        CertificateStatus status)
    {
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "Not a defined certificate status.");
        }

        return new IssuedKeyMatch(identityId, false, enrolledWithPresentedToken, identityRevoked, status);
    }

    /// <summary>
    /// Returns the match of a certificate of a deleted identity.
    /// </summary>
    /// <remarks>
    /// After an identity is deleted, the authority keeps only the SPKI SHA-256 and the issuance time of its keys,
    /// so <see cref="EnrollmentRules.Decide"/> refuses the key with <c>identity_revoked</c> whatever token enrolled
    /// the identity.
    /// A revoked presented token gets <c>token_invalid</c> instead, since it authenticates nothing but a replay.
    /// <see cref="RenewalRules.Decide"/> refuses the key with <c>invalid_request</c>, as it does any key of another
    /// identity.
    /// </remarks>
    public static IssuedKeyMatch ForDeletedIdentity()
    {
        return DeletedIdentity;
    }
}
