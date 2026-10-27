namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// What the authority does with a renew request.
/// </summary>
public enum RenewalOutcome
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering an outcome would change what an existing host does.
    // When adding an outcome, give it the next unused value;
    // values start at 1 so that an uninitialized outcome is not a valid one.

    /// <summary>
    /// Issue a pending certificate for the CSR key, with the <see cref="IdentityCertificateIssuer"/> overload that
    /// takes the decision, and retire the identity's previous pending certificate, if any.
    /// </summary>
    IssuePendingCertificate = 1,

    /// <summary>
    /// Return the chain of the identity's pending certificate, which holds the CSR key,
    /// so that a device recovers a lost renew response.
    /// </summary>
    ReturnPendingCertificate = 2,

    /// <summary>
    /// Refuse the request with <see cref="RenewalDecision.Error"/>.
    /// </summary>
    Reject = 3,
}
