namespace Devolutions.AgentIdentity;

/// <summary>
/// The status of a certificate the authority issued to an identity.
/// </summary>
public enum CertificateStatus
{
    /// <summary>
    /// Issued by renew and not yet confirmed.
    /// </summary>
    Pending,

    /// <summary>
    /// The certificate the identity authenticates with.
    /// </summary>
    Current,

    /// <summary>
    /// Replaced by a confirmed certificate.
    /// </summary>
    Retired,
}
