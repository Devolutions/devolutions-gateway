namespace Devolutions.AgentIdentity;

/// <summary>
/// An identity that a signed request, or the proof that authenticates an agent channel stream, proved.
/// </summary>
/// <remarks>
/// Only request authentication and the channel handshake create one, so code that takes this type acts for an
/// identity that a signature check established, never for one taken from a value that the agent or a caller sent.
/// </remarks>
public sealed class AuthenticatedIdentity
{
    internal AuthenticatedIdentity(
        Guid identityId,
        string certificateThumbprint,
        CertificateStatus certificateStatus,
        DateTimeOffset certificateNotBefore,
        DateTimeOffset certificateNotAfter,
        AgentOperation operation)
    {
        IdentityId = identityId;
        CertificateThumbprint = certificateThumbprint;
        CertificateStatus = certificateStatus;
        CertificateNotBefore = certificateNotBefore;
        CertificateNotAfter = certificateNotAfter;
        Operation = operation;
    }

    /// <summary>
    /// The identity that the request proved.
    /// </summary>
    public Guid IdentityId { get; }

    /// <summary>
    /// The thumbprint of the certificate whose key signed the request.
    /// </summary>
    public string CertificateThumbprint { get; }

    /// <summary>
    /// The status of the certificate whose key signed the request, as the registry held it when the request
    /// authenticated.
    /// </summary>
    /// <remarks>
    /// It is <see cref="CertificateStatus.Pending"/> or <see cref="CertificateStatus.Current"/>,
    /// or <see cref="CertificateStatus.Retired"/> for an agent channel stream whose certificate a confirm retired
    /// during the handshake.
    /// </remarks>
    public CertificateStatus CertificateStatus { get; }

    /// <summary>
    /// The <c>notBefore</c> of the certificate whose key signed the request.
    /// </summary>
    public DateTimeOffset CertificateNotBefore { get; }

    /// <summary>
    /// The <c>notAfter</c> of the certificate whose key signed the request.
    /// </summary>
    public DateTimeOffset CertificateNotAfter { get; }

    /// <summary>
    /// The operation that the request was signed for.
    /// </summary>
    public AgentOperation Operation { get; }
}
