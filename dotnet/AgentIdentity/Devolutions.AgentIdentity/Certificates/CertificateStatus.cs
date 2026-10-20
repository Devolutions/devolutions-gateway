namespace Devolutions.AgentIdentity;

/// <summary>
/// The status of a certificate the authority issued to an identity.
/// </summary>
public enum CertificateStatus
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering a status would change what an existing host reports.
    // When adding a status, give it the next unused value;
    // values start at 1 so that an uninitialized status is not a valid one.

    /// <summary>
    /// Issued by renew and not yet confirmed.
    /// </summary>
    Pending = 1,

    /// <summary>
    /// The certificate the identity authenticates with.
    /// </summary>
    Current = 2,

    /// <summary>
    /// Replaced by a confirmed certificate.
    /// </summary>
    Retired = 3,
}
