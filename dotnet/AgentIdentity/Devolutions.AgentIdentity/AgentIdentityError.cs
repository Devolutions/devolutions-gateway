using System.Buffers;
using System.Text.Json;
using Grpc.Core;

namespace Devolutions.AgentIdentity;

/// <summary>
/// An error response of the agent-facing protocol: a code, the HTTP status that carries it,
/// and a fixed English message.
/// </summary>
/// <remarks>
/// Each message is fixed for its error, so it never repeats request data, a token or a secret.
/// </remarks>
public sealed class AgentIdentityError
{
    // UNTESTED: every message is a constant sentence.
    // Error bodies, trailers and agent logs carry the message,
    // so one built from request data could leak a token or a secret.
    // When adding an error, give it a constant message and keep this constructor private.
    private AgentIdentityError(AgentIdentityErrorCode code, int httpStatusCode, string message)
    {
        Code = code;
        HttpStatusCode = httpStatusCode;
        Message = message;
    }

    /// <summary>
    /// The error code.
    /// </summary>
    public AgentIdentityErrorCode Code { get; }

    /// <summary>
    /// The HTTP status of the response.
    /// </summary>
    public int HttpStatusCode { get; }

    /// <summary>
    /// A fixed English sentence describing the error.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// The error for a request body that is not valid JSON or does not have the expected shape:
    /// <c>400 invalid_request</c>.
    /// </summary>
    public static AgentIdentityError MalformedBody { get; } =
        new(AgentIdentityErrorCode.InvalidRequest, 400, "The request body is malformed.");

    /// <summary>
    /// The error for a path under the agent identity base path that no endpoint serves: <c>404 invalid_request</c>.
    /// </summary>
    public static AgentIdentityError UnknownRoute { get; } =
        new(AgentIdentityErrorCode.InvalidRequest, 404, "No endpoint serves this path.");

    /// <summary>
    /// The error for an HTTP method that the endpoint does not accept: <c>405 invalid_request</c>.
    /// </summary>
    public static AgentIdentityError MethodNotAllowed { get; } =
        new(AgentIdentityErrorCode.InvalidRequest, 405, "The endpoint does not accept this method.");

    /// <summary>
    /// The error for a request body larger than <see cref="AgentIdentityProtocol.MaxRequestBodyBytes"/>:
    /// <c>413 invalid_request</c>.
    /// </summary>
    public static AgentIdentityError BodyTooLarge { get; } =
        new(AgentIdentityErrorCode.InvalidRequest, 413, "The request body is larger than 64 KiB.");

    /// <summary>
    /// The error for an unexpected server failure: <c>500 unavailable</c>.
    /// </summary>
    public static AgentIdentityError UnexpectedFailure { get; } =
        new(AgentIdentityErrorCode.Unavailable, 500, "The server failed unexpectedly.");

    /// <summary>
    /// The error for a server that is overloaded or missing a dependency: <c>503 unavailable</c>.
    /// </summary>
    /// <remarks>
    /// When the host sheds load, it also sends a <c>Retry-After</c> header, which the agent honors;
    /// the library writes no HTTP headers.
    /// </remarks>
    public static AgentIdentityError ServiceUnavailable { get; } =
        new(
            AgentIdentityErrorCode.Unavailable,
            503,
            "The server is overloaded or a service it depends on is unavailable.");

    /// <summary>
    /// Returns the error for a code,
    /// with the HTTP status of <see cref="AgentIdentityErrorCodeExtensions.ToHttpStatusCode"/>.
    /// </summary>
    /// <param name="code">The error code.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="code"/> is not a defined code.</exception>
    public static AgentIdentityError From(AgentIdentityErrorCode code)
    {
        return new AgentIdentityError(code, code.ToHttpStatusCode(), MessageFor(code));
    }

    /// <summary>
    /// Writes the body of the error response:
    /// a UTF-8 JSON object with the members <c>error</c>, <c>message</c> and <c>server_time</c>.
    /// </summary>
    /// <param name="serverTime">
    /// The server's current time,
    /// which the agent uses to correct its clock after <see cref="AgentIdentityErrorCode.ClockSkew"/>.
    /// </param>
    public byte[] ToJsonBody(DateTimeOffset serverTime)
    {
        ArrayBufferWriter<byte> buffer = new();

        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("error", Code.ToWireValue());
            writer.WriteString("message", Message);
            writer.WriteString("server_time", AgentIdentityProtocol.FormatTimestamp(serverTime));
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Creates the exception that closes an agent channel stream with this error.
    /// </summary>
    /// <remarks>
    /// The exception carries the status of <see cref="AgentIdentityErrorCodeExtensions.ToGrpcStatusCode"/>
    /// and the trailers <c>error-code</c> and <c>server-time</c>.
    /// </remarks>
    /// <param name="serverTime">
    /// The server's current time,
    /// which the agent uses to correct its clock after <see cref="AgentIdentityErrorCode.ClockSkew"/>.
    /// </param>
    public RpcException ToRpcException(DateTimeOffset serverTime)
    {
        Metadata trailers = new()
        {
            { "error-code", Code.ToWireValue() },
            { "server-time", AgentIdentityProtocol.FormatTimestamp(serverTime) },
        };

        return new RpcException(new Status(Code.ToGrpcStatusCode(), Message), trailers);
    }

    private static string MessageFor(AgentIdentityErrorCode code)
    {
        return code switch
        {
            AgentIdentityErrorCode.TokenInvalid => "The enrollment token is not valid.",
            AgentIdentityErrorCode.TokenExhausted => "The enrollment token has reached its use limit.",
            AgentIdentityErrorCode.TokenExpired => "The enrollment token has expired.",
            AgentIdentityErrorCode.IdentityRevoked => "The identity is revoked.",
            AgentIdentityErrorCode.IdentityUnknown => "The certificate is not registered, or its identity was deleted.",
            AgentIdentityErrorCode.CertificateExpired => "The certificate has expired.",
            AgentIdentityErrorCode.SignatureInvalid => "The signature is not valid.",
            AgentIdentityErrorCode.ClockSkew => "The signature time is outside the accepted window.",
            AgentIdentityErrorCode.InvalidRequest => "The request body, CSR or metadata is not valid.",
            AgentIdentityErrorCode.Unavailable => "The server cannot serve the request now.",
            _ => throw AgentIdentityErrorCodeExtensions.UndefinedCode(code),
        };
    }
}
