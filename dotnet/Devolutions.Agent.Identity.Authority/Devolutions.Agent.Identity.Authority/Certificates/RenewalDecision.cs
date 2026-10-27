namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// What the authority does with a renew request, as <see cref="RenewalRules.Decide"/> decides it.
/// </summary>
public sealed class RenewalDecision
{
    private RenewalDecision(
        RenewalOutcome outcome,
        AuthenticatedIdentity? renewing,
        ReadOnlyMemory<byte> subjectPublicKeyInfoSha256,
        AgentIdentityError? error,
        string? failureDetail)
    {
        Outcome = outcome;
        Renewing = renewing;
        SubjectPublicKeyInfoSha256 = subjectPublicKeyInfoSha256;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// What the authority does with the request.
    /// </summary>
    public RenewalOutcome Outcome { get; }

    /// <summary>
    /// The SHA-256 digest of the <c>SubjectPublicKeyInfo</c> of the CSR that the decision was made for,
    /// its <see cref="CertificateSigningRequest.SubjectPublicKeyInfoSha256"/>,
    /// when <see cref="Outcome"/> is <see cref="RenewalOutcome.IssuePendingCertificate"/>; otherwise empty.
    /// </summary>
    /// <remarks>
    /// The decision holds only for the key whose lookup it was made from,
    /// so the <see cref="IdentityCertificateIssuer"/> overload that takes the decision certifies no other key.
    /// </remarks>
    public ReadOnlyMemory<byte> SubjectPublicKeyInfoSha256 { get; }

    /// <summary>
    /// The error that refuses the request, <c>400 invalid_request</c>,
    /// when <see cref="Outcome"/> is <see cref="RenewalOutcome.Reject"/>; otherwise null.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// The rule that refuses the request, for the host's logs,
    /// when <see cref="Outcome"/> is <see cref="RenewalOutcome.Reject"/>; otherwise null.
    /// </summary>
    public string? FailureDetail { get; }

    // The identity that the renew request proved, when the decision issues a pending certificate; otherwise null.
    // Internal so that the certificate is issued for the identity that the decision was made for, and no other.
    internal AuthenticatedIdentity? Renewing { get; }

    internal static RenewalDecision IssuePendingCertificate(
        AuthenticatedIdentity renewing,
        ReadOnlyMemory<byte> subjectPublicKeyInfoSha256)
    {
        return new RenewalDecision(
            RenewalOutcome.IssuePendingCertificate,
            renewing,
            subjectPublicKeyInfoSha256,
            null,
            null);
    }

    internal static RenewalDecision ReturnPendingCertificate()
    {
        return new RenewalDecision(
            RenewalOutcome.ReturnPendingCertificate,
            null,
            ReadOnlyMemory<byte>.Empty,
            null,
            null);
    }

    internal static RenewalDecision Reject(string failureDetail)
    {
        return new RenewalDecision(
            RenewalOutcome.Reject,
            null,
            ReadOnlyMemory<byte>.Empty,
            AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest),
            failureDetail);
    }
}
