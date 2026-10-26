using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The root that issues identity certificates, implemented by the host, which keeps the root's private key.
/// </summary>
public interface IRootSigner
{
    /// <summary>
    /// The root certificate, which must have a subject key identifier,
    /// and fit the chain profile of CONTRACT.agent-identity.md §4: a P-256 or P-384 key, basicConstraints with cA set,
    /// and key usage with keyCertSign.
    /// </summary>
    /// <remarks>
    /// Its subject becomes the issuer of each identity certificate,
    /// and its subject key identifier becomes their authority key identifier.
    /// </remarks>
    X509Certificate2 Certificate { get; }

    /// <summary>
    /// Signs identity certificates with the private key of <see cref="Certificate"/>,
    /// with ecdsa-with-SHA256 for a P-256 key or ecdsa-with-SHA384 for a P-384 key.
    /// </summary>
    X509SignatureGenerator SignatureGenerator { get; }
}
