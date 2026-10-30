using System.Diagnostics.CodeAnalysis;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The outcome of <see cref="CertificateSigningRequest.Validate"/>: a validated request, or the error that rejects it.
/// </summary>
/// <remarks>
/// The error is <c>400 invalid_request</c>.
/// </remarks>
public sealed class CsrValidationResult : AgentIdentityResult
{
    private static readonly AgentIdentityError InvalidRequest =
        AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest);

    private CsrValidationResult(CertificateSigningRequest? csr, AgentIdentityError? error, string? failureDetail)
        : base(error, failureDetail)
    {
        Csr = csr;
    }

    /// <summary>
    /// Whether the request is valid.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Csr))]
    public override bool Succeeded => Csr is not null;

    /// <summary>
    /// The validated request, when <see cref="Succeeded"/> is true.
    /// </summary>
    public CertificateSigningRequest? Csr { get; }

    internal static CsrValidationResult Success(CertificateSigningRequest csr)
    {
        return new CsrValidationResult(csr, null, null);
    }

    internal static CsrValidationResult Failure(string detail)
    {
        return new CsrValidationResult(null, InvalidRequest, detail);
    }
}
