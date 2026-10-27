namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// What the authority does with an enroll request, as <see cref="EnrollmentRules.Decide"/> decides it.
/// </summary>
public sealed class EnrollmentDecision
{
    private EnrollmentDecision(
        EnrollmentOutcome outcome,
        Guid? newIdentityId,
        string? enrollmentUrl,
        int? expectedIdentitiesCreated,
        ReadOnlyMemory<byte> subjectPublicKeyInfoSha256,
        Guid? existingIdentityId,
        AgentIdentityError? error,
        string? failureDetail)
    {
        Outcome = outcome;
        NewIdentityId = newIdentityId;
        EnrollmentUrl = enrollmentUrl;
        ExpectedIdentitiesCreated = expectedIdentitiesCreated;
        SubjectPublicKeyInfoSha256 = subjectPublicKeyInfoSha256;
        ExistingIdentityId = existingIdentityId;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// What the authority does with the request.
    /// </summary>
    public EnrollmentOutcome Outcome { get; }

    /// <summary>
    /// The ID that the library minted for the new identity, a random UUID unique to this decision,
    /// when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.CreateIdentity"/>; otherwise null.
    /// </summary>
    /// <remarks>
    /// The authority creates the identity under this ID and answers the request with it.
    /// It issues the identity's certificate by passing this decision to the <see cref="IdentityCertificateIssuer"/>
    /// overload that takes it, so that no certificate is issued for an identity that no enrollment created.
    /// </remarks>
    public Guid? NewIdentityId { get; }

    /// <summary>
    /// The enrollment URL that every certificate of the new identity names, the token's <c>u</c> without trailing
    /// slashes, when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.CreateIdentity"/>; otherwise null.
    /// </summary>
    /// <remarks>
    /// The <see cref="IdentityCertificateIssuer"/> overload that takes this decision writes it into the certificate,
    /// and the authority keeps it with the identity so that each renewal names the same URL.
    /// </remarks>
    public string? EnrollmentUrl { get; }

    /// <summary>
    /// The token's <see cref="EnrollmentTokenState.IdentitiesCreated"/> that the decision was made from,
    /// when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.CreateIdentity"/>; otherwise null.
    /// </summary>
    /// <remarks>
    /// The authority counts the token use in the transaction that creates the identity, with an update that succeeds
    /// only while the stored count is still below the token's <see cref="EnrollmentTokenState.MaxUses"/>,
    /// or, stricter, only while it still equals this value,
    /// so that concurrent enrollments never create more identities than that limit.
    /// When the update fails, the authority decides again from the stored state and acts on the new decision,
    /// discarding any certificate issued from this one.
    /// </remarks>
    public int? ExpectedIdentitiesCreated { get; }

    /// <summary>
    /// The SHA-256 digest of the <c>SubjectPublicKeyInfo</c> of the CSR that the decision was made for,
    /// its <see cref="CertificateSigningRequest.SubjectPublicKeyInfoSha256"/>,
    /// when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.CreateIdentity"/>; otherwise empty.
    /// </summary>
    /// <remarks>
    /// The decision holds only for the key whose lookup it was made from,
    /// so the <see cref="IdentityCertificateIssuer"/> overload that takes the decision certifies no other key.
    /// </remarks>
    public ReadOnlyMemory<byte> SubjectPublicKeyInfoSha256 { get; }

    /// <summary>
    /// The identity whose enrollment the request replays,
    /// when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.ReturnExistingIdentity"/>; otherwise null.
    /// </summary>
    public Guid? ExistingIdentityId { get; }

    /// <summary>
    /// The error that refuses the request, when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.Reject"/>;
    /// otherwise null.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// The rule that refuses the request, for the host's logs,
    /// when <see cref="Outcome"/> is <see cref="EnrollmentOutcome.Reject"/>; otherwise null.
    /// </summary>
    public string? FailureDetail { get; }

    internal static EnrollmentDecision CreateIdentity(
        Guid newIdentityId,
        string enrollmentUrl,
        int expectedIdentitiesCreated,
        ReadOnlyMemory<byte> subjectPublicKeyInfoSha256)
    {
        return new EnrollmentDecision(
            EnrollmentOutcome.CreateIdentity,
            newIdentityId,
            enrollmentUrl,
            expectedIdentitiesCreated,
            subjectPublicKeyInfoSha256,
            null,
            null,
            null);
    }

    internal static EnrollmentDecision ReturnExistingIdentity(Guid identityId)
    {
        return new EnrollmentDecision(
            EnrollmentOutcome.ReturnExistingIdentity,
            null,
            null,
            null,
            ReadOnlyMemory<byte>.Empty,
            identityId,
            null,
            null);
    }

    internal static EnrollmentDecision Reject(AgentIdentityErrorCode code, string failureDetail)
    {
        return new EnrollmentDecision(
            EnrollmentOutcome.Reject,
            null,
            null,
            null,
            ReadOnlyMemory<byte>.Empty,
            null,
            AgentIdentityError.From(code),
            failureDetail);
    }
}
