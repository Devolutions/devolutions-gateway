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
        Guid? existingIdentityId,
        AgentIdentityError? error,
        string? failureDetail)
    {
        Outcome = outcome;
        NewIdentityId = newIdentityId;
        EnrollmentUrl = enrollmentUrl;
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

    internal static EnrollmentDecision CreateIdentity(Guid newIdentityId, string enrollmentUrl)
    {
        return new EnrollmentDecision(EnrollmentOutcome.CreateIdentity, newIdentityId, enrollmentUrl, null, null, null);
    }

    internal static EnrollmentDecision ReturnExistingIdentity(Guid identityId)
    {
        return new EnrollmentDecision(EnrollmentOutcome.ReturnExistingIdentity, null, null, identityId, null, null);
    }

    internal static EnrollmentDecision Reject(AgentIdentityErrorCode code, string failureDetail)
    {
        return new EnrollmentDecision(
            EnrollmentOutcome.Reject,
            null,
            null,
            null,
            AgentIdentityError.From(code),
            failureDetail);
    }
}
