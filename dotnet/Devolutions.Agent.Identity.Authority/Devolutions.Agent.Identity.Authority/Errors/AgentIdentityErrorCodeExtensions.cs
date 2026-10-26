using Grpc.Core;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Maps an <see cref="AgentIdentityErrorCode"/> to its wire value and to the statuses that carry it.
/// </summary>
public static class AgentIdentityErrorCodeExtensions
{
    /// <summary>
    /// Returns the value sent in the <c>error</c> member of an error body and in the <c>error-code</c> trailer,
    /// such as <c>token_invalid</c>.
    /// </summary>
    /// <param name="code">The error code.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="code"/> is not a defined code.</exception>
    public static string ToWireValue(this AgentIdentityErrorCode code)
    {
        return code switch
        {
            AgentIdentityErrorCode.TokenInvalid => "token_invalid",
            AgentIdentityErrorCode.TokenExhausted => "token_exhausted",
            AgentIdentityErrorCode.TokenExpired => "token_expired",
            AgentIdentityErrorCode.IdentityRevoked => "identity_revoked",
            AgentIdentityErrorCode.IdentityUnknown => "identity_unknown",
            AgentIdentityErrorCode.CertificateExpired => "certificate_expired",
            AgentIdentityErrorCode.SignatureInvalid => "signature_invalid",
            AgentIdentityErrorCode.ClockSkew => "clock_skew",
            AgentIdentityErrorCode.InvalidRequest => "invalid_request",
            AgentIdentityErrorCode.Unavailable => "unavailable",
            AgentIdentityErrorCode.TokenUrlMismatch => "token_url_mismatch",
            _ => throw UndefinedCode(code),
        };
    }

    /// <summary>
    /// Returns the HTTP status of a response carrying the code.
    /// </summary>
    /// <remarks>
    /// <see cref="AgentIdentityErrorCode.Unavailable"/> maps to 500, the status of an unexpected failure.
    /// The framework-level errors of <see cref="AgentIdentityError"/>,
    /// such as <see cref="AgentIdentityError.ServiceUnavailable"/>, carry other statuses with the same codes.
    /// </remarks>
    /// <param name="code">The error code.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="code"/> is not a defined code.</exception>
    public static int ToHttpStatusCode(this AgentIdentityErrorCode code)
    {
        return code switch
        {
            AgentIdentityErrorCode.TokenInvalid => 401,
            AgentIdentityErrorCode.TokenExhausted => 403,
            AgentIdentityErrorCode.TokenExpired => 401,
            AgentIdentityErrorCode.IdentityRevoked => 403,
            AgentIdentityErrorCode.IdentityUnknown => 401,
            AgentIdentityErrorCode.CertificateExpired => 401,
            AgentIdentityErrorCode.SignatureInvalid => 401,
            AgentIdentityErrorCode.ClockSkew => 401,
            AgentIdentityErrorCode.InvalidRequest => 400,
            AgentIdentityErrorCode.Unavailable => 500,
            AgentIdentityErrorCode.TokenUrlMismatch => 403,
            _ => throw UndefinedCode(code),
        };
    }

    /// <summary>
    /// Returns the gRPC status that closes an agent channel stream with the code.
    /// </summary>
    /// <param name="code">The error code.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="code"/> is not a defined code.</exception>
    public static StatusCode ToGrpcStatusCode(this AgentIdentityErrorCode code)
    {
        return code switch
        {
            AgentIdentityErrorCode.IdentityRevoked => StatusCode.PermissionDenied,
            AgentIdentityErrorCode.InvalidRequest => StatusCode.InvalidArgument,
            AgentIdentityErrorCode.Unavailable => StatusCode.Unavailable,
            AgentIdentityErrorCode.TokenInvalid
                or AgentIdentityErrorCode.TokenExhausted
                or AgentIdentityErrorCode.TokenExpired
                or AgentIdentityErrorCode.TokenUrlMismatch
                or AgentIdentityErrorCode.IdentityUnknown
                or AgentIdentityErrorCode.CertificateExpired
                or AgentIdentityErrorCode.SignatureInvalid
                or AgentIdentityErrorCode.ClockSkew => StatusCode.Unauthenticated,
            _ => throw UndefinedCode(code),
        };
    }

    internal static ArgumentOutOfRangeException UndefinedCode(AgentIdentityErrorCode code)
    {
        return new ArgumentOutOfRangeException(nameof(code), code, "Not a defined agent identity error code.");
    }
}
