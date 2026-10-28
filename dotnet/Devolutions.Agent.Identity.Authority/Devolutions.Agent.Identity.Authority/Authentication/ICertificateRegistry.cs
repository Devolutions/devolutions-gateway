namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Finds the certificates that the authority issued, by thumbprint.
/// </summary>
/// <remarks>
/// The host implements it over its own storage.
/// A signed request names its certificate only by thumbprint, so this lookup is the only way it is resolved.
/// </remarks>
public interface ICertificateRegistry
{
    /// <summary>
    /// Finds the certificate with a thumbprint.
    /// </summary>
    /// <param name="thumbprint">
    /// The thumbprint, <c>base64url(SHA-256(certificate DER))</c>,
    /// as <see cref="AgentIdentityProtocol.ComputeThumbprint"/> computes it.
    /// </param>
    /// <param name="cancellationToken">A token that cancels the lookup.</param>
    /// <returns>
    /// The certificate in any status, including <see cref="CertificateStatus.Retired"/>,
    /// or null when the authority issued no certificate with this thumbprint or deleted its identity.
    /// </returns>
    ValueTask<RegisteredCertificate?> FindByThumbprintAsync(string thumbprint, CancellationToken cancellationToken);
}
