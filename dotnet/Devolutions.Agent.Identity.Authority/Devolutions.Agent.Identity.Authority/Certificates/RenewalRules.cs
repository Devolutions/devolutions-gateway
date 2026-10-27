namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Applies the renewal rules that every authority shares to a renew request.
/// </summary>
public static class RenewalRules
{
    /// <summary>
    /// Decides whether a renew request gets a new pending certificate, gets the identity's pending certificate again,
    /// or is refused, from the issued certificate that holds the key of its CSR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host calls this once the request authenticated and its body, CSR and metadata are valid.
    /// The key of the identity's pending certificate gets that certificate's chain again,
    /// so that a device recovers a lost renew response.
    /// Any other issued key gets <c>invalid_request</c>:
    /// the identity's current or retired key, any key of another identity, revoked or not,
    /// and any key of a deleted identity.
    /// A key never issued gets a new pending certificate, which retires the identity's previous pending certificate,
    /// if any, and which the <see cref="IdentityCertificateIssuer"/> overload that takes the decision issues
    /// for <paramref name="renewing"/> and the key of <paramref name="csr"/> alone.
    /// Renewal never promotes a certificate; only <c>confirm</c> does.
    /// </para>
    /// <para>
    /// Every accepted request, including one that gets the pending certificate again, replaces the identity's metadata.
    /// The decision holds only for the state it was made from.
    /// The host stores the pending certificate, inserts its key under a unique index of every issued key,
    /// and retires the pending certificate that the identity holds then, in one transaction,
    /// and decides again from the stored state when the index refuses the key, acting on the new decision,
    /// so that of two concurrent renewals with one CSR key,
    /// exactly one issues the certificate and the other gets that pending certificate.
    /// </para>
    /// </remarks>
    /// <param name="renewing">
    /// The identity that the renew request proved, as <see cref="RequestAuthenticator.AuthenticateAsync"/> returns it
    /// for <see cref="AgentOperation.Renew"/>.
    /// </param>
    /// <param name="csr">The request's validated CSR.</param>
    /// <param name="keyMatch">The issued certificate whose public key is the CSR key, or null when none has it.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="renewing"/> or <paramref name="csr"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="renewing"/> was authenticated for another operation than <c>renew</c>.
    /// </exception>
    public static RenewalDecision Decide(
        AuthenticatedIdentity renewing,
        CertificateSigningRequest csr,
        IssuedKeyMatch? keyMatch)
    {
        ArgumentNullException.ThrowIfNull(renewing);

        if (renewing.Operation != AgentOperation.Renew)
        {
            throw new ArgumentException("The identity was not authenticated by a renew request.", nameof(renewing));
        }

        ArgumentNullException.ThrowIfNull(csr);

        if (keyMatch is null)
        {
            return RenewalDecision.IssuePendingCertificate(renewing, csr.SubjectPublicKeyInfoSha256);
        }

        // A public key belongs to one certificate lineage, so only the pending key of the identity itself is a retry.
        if (keyMatch.IdentityDeleted)
        {
            return RenewalDecision.Reject("The CSR key belongs to a deleted identity.");
        }

        if (keyMatch.IdentityId != renewing.IdentityId)
        {
            return RenewalDecision.Reject("The CSR key belongs to another identity.");
        }

        if (keyMatch.Status != CertificateStatus.Pending)
        {
            return RenewalDecision.Reject("The CSR key belongs to a current or retired certificate of the identity.");
        }

        return RenewalDecision.ReturnPendingCertificate;
    }
}
