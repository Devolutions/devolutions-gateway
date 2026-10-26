using System.Diagnostics.CodeAnalysis;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The outcome of parsing a request body: the validated body, or the error that rejects it.
/// </summary>
/// <typeparam name="TBody">
/// The body type: <see cref="EnrollRequestBody"/>, <see cref="RenewRequestBody"/>, <see cref="ConfirmRequestBody"/>
/// or <see cref="CheckInRequestBody"/>.
/// </typeparam>
/// <remarks>
/// The error is <c>400 invalid_request</c>.
/// <see cref="AgentIdentityResult.FailureDetail"/> never repeats a value from the body, not even a metadata key:
/// it names a metadata entry by its position.
/// </remarks>
public sealed class RequestBodyParseResult<TBody> : AgentIdentityResult
    where TBody : class
{
    private static readonly AgentIdentityError InvalidRequest =
        AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest);

    private RequestBodyParseResult(TBody? body, AgentIdentityError? error, string? failureDetail)
        : base(error, failureDetail)
    {
        Body = body;
    }

    /// <summary>
    /// Whether the body is valid.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Body))]
    public override bool Succeeded => Body is not null;

    /// <summary>
    /// The validated body, when <see cref="Succeeded"/> is true.
    /// </summary>
    public TBody? Body { get; }

    internal static RequestBodyParseResult<TBody> Success(TBody body)
    {
        return new RequestBodyParseResult<TBody>(body, null, null);
    }

    internal static RequestBodyParseResult<TBody> Failure(string detail)
    {
        return new RequestBodyParseResult<TBody>(null, InvalidRequest, detail);
    }
}
