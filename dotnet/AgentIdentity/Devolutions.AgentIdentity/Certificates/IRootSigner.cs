using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The root that issues identity certificates, implemented by the host, which keeps the root's private key.
/// </summary>
public interface IRootSigner
{
    /// <summary>
    /// The root certificate, which must have a subject key identifier.
    /// </summary>
    /// <remarks>
    /// Its subject becomes the issuer of each identity certificate,
    /// and its subject key identifier becomes their authority key identifier.
    /// </remarks>
    X509Certificate2 Certificate { get; }

    /// <summary>
    /// Signs identity certificates with the private key of <see cref="Certificate"/>.
    /// </summary>
    X509SignatureGenerator SignatureGenerator { get; }
}
