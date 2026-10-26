namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// A certificate that the authority issued to an identity, with the state the authority keeps beside it.
/// </summary>
/// <remarks>
/// Request authentication reads the validity and the public key from <see cref="CertificateDer"/>,
/// so the host stores no copy of them.
/// </remarks>
public sealed class RegisteredCertificate
{
    /// <summary>
    /// Creates a registered certificate.
    /// </summary>
    /// <param name="identityId">The identity that the certificate was issued to.</param>
    /// <param name="certificateDer">The DER encoding of the certificate, exactly as the authority issued it.</param>
    /// <param name="status">The status of the certificate.</param>
    /// <param name="identityRevoked">Whether the identity is revoked.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="status"/> is not a defined status.</exception>
    public RegisteredCertificate(
        Guid identityId,
        ReadOnlyMemory<byte> certificateDer,
        CertificateStatus status,
        bool identityRevoked)
    {
        // An undefined status is a host bug,
        // which must fail as a server error rather than draw an outcome that is terminal for the agent.
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "Not a defined certificate status.");
        }

        IdentityId = identityId;
        CertificateDer = certificateDer;
        Status = status;
        IdentityRevoked = identityRevoked;
    }

    /// <summary>
    /// The identity that the certificate was issued to.
    /// </summary>
    public Guid IdentityId { get; }

    /// <summary>
    /// The DER encoding of the certificate, whose thumbprint the registry looked up.
    /// </summary>
    public ReadOnlyMemory<byte> CertificateDer { get; }

    /// <summary>
    /// The status of the certificate.
    /// </summary>
    public CertificateStatus Status { get; }

    /// <summary>
    /// Whether the identity is revoked.
    /// </summary>
    public bool IdentityRevoked { get; }
}
