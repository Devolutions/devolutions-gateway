namespace Devolutions.AgentIdentity;

/// <summary>
/// What the authority does with an enroll request, as <see cref="EnrollmentRules.Decide"/> decides it.
/// </summary>
public sealed class EnrollmentDecision
{
    private EnrollmentDecision(
        EnrollmentOutcome outcome,
        Guid? existingIdentityId,
        AgentIdentityError? error,
        string? failureDetail)
    {
        Outcome = outcome;
        ExistingIdentityId = existingIdentityId;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// What the authority does with the request.
    /// </summary>
    public EnrollmentOutcome Outcome { get; }

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

    internal static EnrollmentDecision CreateIdentity { get; } =
        new(EnrollmentOutcome.CreateIdentity, null, null, null);

    internal static EnrollmentDecision ReturnExistingIdentity(Guid identityId)
    {
        return new EnrollmentDecision(EnrollmentOutcome.ReturnExistingIdentity, identityId, null, null);
    }

    internal static EnrollmentDecision Reject(AgentIdentityErrorCode code, string failureDetail)
    {
        return new EnrollmentDecision(EnrollmentOutcome.Reject, null, AgentIdentityError.From(code), failureDetail);
    }
}
