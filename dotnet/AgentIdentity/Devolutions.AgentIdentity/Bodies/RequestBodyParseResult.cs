using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of parsing a request body: the validated body, or the error that rejects it.
/// </summary>
/// <typeparam name="TBody">
/// The body type: <see cref="EnrollRequestBody"/>, <see cref="RenewRequestBody"/>, <see cref="ConfirmRequestBody"/>
/// or <see cref="CheckInRequestBody"/>.
/// </typeparam>
public sealed class RequestBodyParseResult<TBody>
    where TBody : class
{
    private static readonly AgentIdentityError InvalidRequest =
        AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest);

    private RequestBodyParseResult(TBody? body, AgentIdentityError? error, string? failureDetail)
    {
        Succeeded = body is not null;
        Body = body;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the body is valid.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Body))]
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The validated body, when <see cref="Succeeded"/> is true.
    /// </summary>
    public TBody? Body { get; }

    /// <summary>
    /// <c>400 invalid_request</c>, when <see cref="Succeeded"/> is false.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// Why the body is invalid, for the host's logs, when <see cref="Succeeded"/> is false.
    /// </summary>
    /// <remarks>
    /// The detail never repeats a value from the body, and quotes a metadata key only when the key itself is valid.
    /// </remarks>
    public string? FailureDetail { get; }

    internal static RequestBodyParseResult<TBody> Success(TBody body)
    {
        return new RequestBodyParseResult<TBody>(body, null, null);
    }

    internal static RequestBodyParseResult<TBody> Failure(string detail)
    {
        return new RequestBodyParseResult<TBody>(null, InvalidRequest, detail);
    }
}
