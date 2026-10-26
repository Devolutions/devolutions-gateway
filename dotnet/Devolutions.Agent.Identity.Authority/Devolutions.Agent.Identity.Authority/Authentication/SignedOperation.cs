namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The signature profile of one operation: its tag, its covered components and the certificate validity it accepts.
/// </summary>
/// <remarks>
/// These are the rows of the table in CONTRACT.agent-identity.md §6.
/// </remarks>
internal sealed class SignedOperation
{
    public const string MethodComponent = "@method";
    public const string ContentDigestComponent = "content-digest";

    private SignedOperation(string tag, string[] coveredComponents, bool hasRenewalGrace)
    {
        Tag = tag;
        CoveredComponents = coveredComponents;
        CoversContentDigest = coveredComponents.Contains(ContentDigestComponent);
        HasRenewalGrace = hasRenewalGrace;
    }

    public static SignedOperation Renew { get; } =
        new("renew", [MethodComponent, ContentDigestComponent], hasRenewalGrace: true);

    public static SignedOperation Confirm { get; } =
        new("confirm", [MethodComponent], hasRenewalGrace: false);

    public static SignedOperation CheckIn { get; } =
        new("check-in", [MethodComponent, ContentDigestComponent], hasRenewalGrace: false);

    public static SignedOperation Connect { get; } =
        new("connect", [MethodComponent], hasRenewalGrace: false);

    public string Tag { get; }

    /// <summary>
    /// The components that a signature for this operation covers, in the order it must list them.
    /// </summary>
    public IReadOnlyList<string> CoveredComponents { get; }

    public bool CoversContentDigest { get; }

    /// <summary>
    /// Whether the operation also accepts a certificate expired by less than its own lifetime.
    /// </summary>
    public bool HasRenewalGrace { get; }

    /// <summary>
    /// Returns the profile of an operation.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="operation"/> is not a defined operation.
    /// </exception>
    public static SignedOperation For(AgentOperation operation)
    {
        return operation switch
        {
            AgentOperation.Renew => Renew,
            AgentOperation.Confirm => Confirm,
            AgentOperation.CheckIn => CheckIn,
            AgentOperation.Connect => Connect,
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Not a defined agent operation."),
        };
    }

    /// <summary>
    /// Tells whether this operation accepts a current or pending certificate with this validity
    /// at <paramref name="now"/>.
    /// </summary>
    /// <remarks>
    /// A certificate is unexpired while <c>now ≤ notAfter</c>, as in RFC 5280 §4.1.2.5.
    /// <c>notBefore</c> is not checked: the authority issued the certificate itself,
    /// so a future <c>notBefore</c> only reflects the authority's clock.
    /// Renewal also accepts a certificate expired by less than its own lifetime.
    /// </remarks>
    public bool AcceptsValidity(DateTimeOffset notBefore, DateTimeOffset notAfter, DateTimeOffset now)
    {
        if (now <= notAfter)
        {
            return true;
        }

        // now < notAfter + (notAfter − notBefore), compared as differences,
        // which cannot overflow for a notAfter close to the largest DateTimeOffset.
        return HasRenewalGrace && now - notAfter < notAfter - notBefore;
    }
}
