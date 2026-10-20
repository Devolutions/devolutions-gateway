using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of <see cref="CertificateSigningRequest.Validate"/>: a validated request, or the error that rejects it.
/// </summary>
public sealed class CsrValidationResult
{
    private static readonly AgentIdentityError InvalidRequest =
        AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest);

    private CsrValidationResult(CertificateSigningRequest? csr, AgentIdentityError? error, string? failureDetail)
    {
        Succeeded = csr is not null;
        Csr = csr;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the request is valid.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Csr))]
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The validated request, when <see cref="Succeeded"/> is true.
    /// </summary>
    public CertificateSigningRequest? Csr { get; }

    /// <summary>
    /// <c>400 invalid_request</c>, when <see cref="Succeeded"/> is false.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// Why the request is invalid, for the host's logs, when <see cref="Succeeded"/> is false.
    /// </summary>
    public string? FailureDetail { get; }

    internal static CsrValidationResult Success(CertificateSigningRequest csr)
    {
        return new CsrValidationResult(csr, null, null);
    }

    internal static CsrValidationResult Failure(string detail)
    {
        return new CsrValidationResult(null, InvalidRequest, detail);
    }
}
