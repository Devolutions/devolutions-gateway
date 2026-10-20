namespace Devolutions.AgentIdentity;

/// <summary>
/// What the authority does with a renew request, as <see cref="RenewalRules.Decide"/> decides it.
/// </summary>
public sealed class RenewalDecision
{
    private RenewalDecision(RenewalOutcome outcome, AgentIdentityError? error, string? failureDetail)
    {
        Outcome = outcome;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// What the authority does with the request.
    /// </summary>
    public RenewalOutcome Outcome { get; }

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

    internal static RenewalDecision IssuePendingCertificate { get; } =
        new(RenewalOutcome.IssuePendingCertificate, null, null);

    internal static RenewalDecision ReturnPendingCertificate { get; } =
        new(RenewalOutcome.ReturnPendingCertificate, null, null);

    internal static RenewalDecision Reject(string failureDetail)
    {
        return new RenewalDecision(
            RenewalOutcome.Reject,
            AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest),
            failureDetail);
    }
}
