namespace Devolutions.AgentIdentity;

/// <summary>
/// The facts about the certificate that authenticated a request:
/// the registry's state for it, and the validity and public key read from the certificate itself.
/// </summary>
internal sealed record VerifiedCertificate(
    Guid IdentityId,
    string Thumbprint,
    CertificateStatus Status,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    byte[] SubjectPublicKeyInfo)
{
    public AuthenticatedIdentity ToIdentity(AgentOperation operation)
    {
        return new AuthenticatedIdentity(IdentityId, Thumbprint, Status, NotBefore, NotAfter, operation);
    }
}
