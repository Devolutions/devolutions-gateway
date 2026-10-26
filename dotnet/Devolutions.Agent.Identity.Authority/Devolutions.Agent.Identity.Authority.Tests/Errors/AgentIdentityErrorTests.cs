using System.Text.Json;
using Grpc.Core;

namespace Devolutions.Agent.Identity.Authority.Tests;

public class AgentIdentityErrorTests
{
    // 12:00:00 UTC given in a +02:00 offset,
    // which CONTRACT.agent-identity.md §1 writes as a UTC timestamp.
    private static readonly DateTimeOffset ServerTime = new(2026, 9, 24, 14, 0, 0, TimeSpan.FromHours(2));

    private const string ServerTimeText = "2026-09-24T12:00:00Z";

    private static readonly string[] FrameworkLevelErrorNames =
    [
        nameof(AgentIdentityError.MalformedBody),
        nameof(AgentIdentityError.UnknownRoute),
        nameof(AgentIdentityError.MethodNotAllowed),
        nameof(AgentIdentityError.BodyTooLarge),
        nameof(AgentIdentityError.UnexpectedFailure),
        nameof(AgentIdentityError.ServiceUnavailable),
    ];

    public static TheoryData<string> PublicErrorNames => new(PublicErrors.Select(error => error.Name));

    // Every error that the library hands out: the error of each code, and each framework-level error.
    private static IEnumerable<(string Name, AgentIdentityError Error)> PublicErrors =>
    [
        .. Enum.GetValues<AgentIdentityErrorCode>().Select(code => ($"From({code})", AgentIdentityError.From(code))),
        .. FrameworkLevelErrorNames.Select(name => (name, FrameworkLevelError(name))),
    ];

    // Column "HTTP".
    [Theory]
    [MemberData(nameof(AgentIdentityErrorCodeTests.HttpStatusCodes), MemberType = typeof(AgentIdentityErrorCodeTests))]
    public void FromCarriesTheCodeWithItsContractStatus(AgentIdentityErrorCode code, int expectedStatus)
    {
        AgentIdentityError error = AgentIdentityError.From(code);

        // The body's `error` is the code.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        Assert.Equal(code, error.Code);
        Assert.Equal(expectedStatus, error.HttpStatusCode);
    }

    // CONTRACT.agent-identity.md §5.4 has no code for the default value of the enum.
    // Framework Design Guidelines, Parameter Design: validate enum parameters, since an enum may hold any integer.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Fact]
    public void FromRejectsAnUndefinedCode()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AgentIdentityError.From(default));
    }

    // Malformed JSON or body → 400 invalid_request;
    // unknown route → 404 invalid_request; wrong method → 405 invalid_request; body too large → 413 invalid_request;
    // an unexpected server failure → 500 unavailable; overload or a missing dependency → 503 unavailable.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(nameof(AgentIdentityError.MalformedBody), 400, AgentIdentityErrorCode.InvalidRequest)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(nameof(AgentIdentityError.UnknownRoute), 404, AgentIdentityErrorCode.InvalidRequest)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(nameof(AgentIdentityError.MethodNotAllowed), 405, AgentIdentityErrorCode.InvalidRequest)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(nameof(AgentIdentityError.BodyTooLarge), 413, AgentIdentityErrorCode.InvalidRequest)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [InlineData(nameof(AgentIdentityError.UnexpectedFailure), 500, AgentIdentityErrorCode.Unavailable)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: spec RFC 9110 §15.6.4
    [InlineData(nameof(AgentIdentityError.ServiceUnavailable), 503, AgentIdentityErrorCode.Unavailable)]
    public void FrameworkLevelErrorHasItsContractStatusAndCode(
        string name,
        int expectedStatus,
        AgentIdentityErrorCode expectedCode)
    {
        AgentIdentityError error = FrameworkLevelError(name);

        Assert.Equal(expectedStatus, error.HttpStatusCode);
        Assert.Equal(expectedCode, error.Code);
    }

    // Every error body, framework-level failures included, carries a `message` of human text.
    // The contract leaves its wording free, so only its presence is checked.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [Theory]
    [MemberData(nameof(PublicErrorNames))]
    public void ErrorHasAHumanMessage(string name)
    {
        AgentIdentityError error = PublicErrors.Single(entry => entry.Name == name).Error;

        Assert.False(string.IsNullOrWhiteSpace(error.Message));
    }

    // CONTRACT.agent-identity.md §5.4 body, with the snake_case keys and the timestamp format of §1.
    // Parsing the raw bytes also rejects a byte order mark, which RFC 8259 §8.1 forbids in a JSON text.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: spec RFC 8259 §8.1
    [Fact]
    public void JsonBodyHasExactlyTheContractMembers()
    {
        byte[] body = AgentIdentityError.From(AgentIdentityErrorCode.ClockSkew).ToJsonBody(ServerTime);

        using JsonDocument document = JsonDocument.Parse(body);
        Dictionary<string, JsonElement> members = document.RootElement
            .EnumerateObject()
            .ToDictionary(member => member.Name, member => member.Value);
        Assert.Equal(["error", "message", "server_time"], members.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("clock_skew", members["error"].GetString());
        Assert.NotEmpty(members["message"].GetString()!);
        Assert.Equal(ServerTimeText, members["server_time"].GetString());
    }

    // CONTRACT.agent-identity.md §7.4: a refused channel opening carries the code's status.
    // §7.3 step 4: invalid `Hello` metadata gets INVALID_ARGUMENT.
    // §7.4: so does a message that cannot be decoded on an authenticated stream.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData(AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData(AgentIdentityErrorCode.IdentityRevoked, StatusCode.PermissionDenied)]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [InlineData(AgentIdentityErrorCode.InvalidRequest, StatusCode.InvalidArgument)]
    // oracle: spec gRPC status codes §Status codes and their use in gRPC
    [InlineData(AgentIdentityErrorCode.Unavailable, StatusCode.Unavailable)]
    public void RpcExceptionHasTheChannelStatus(AgentIdentityErrorCode code, StatusCode expected)
    {
        RpcException exception = AgentIdentityError.From(code).ToRpcException(ServerTime);

        Assert.Equal(expected, exception.StatusCode);
    }

    // Trailers `error-code: <§5.4 code>` and `server-time: <RFC 3339>`, in no stated order.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void RpcExceptionHasExactlyTheContractTrailers()
    {
        RpcException exception = AgentIdentityError.From(AgentIdentityErrorCode.ClockSkew).ToRpcException(ServerTime);

        Assert.Equal(
            [("error-code", "clock_skew"), ("server-time", ServerTimeText)],
            exception.Trailers
                .Select(entry => (entry.Key, entry.Value))
                .OrderBy(entry => entry.Key, StringComparer.Ordinal));
    }

    private static AgentIdentityError FrameworkLevelError(string name)
    {
        return name switch
        {
            nameof(AgentIdentityError.MalformedBody) => AgentIdentityError.MalformedBody,
            nameof(AgentIdentityError.UnknownRoute) => AgentIdentityError.UnknownRoute,
            nameof(AgentIdentityError.MethodNotAllowed) => AgentIdentityError.MethodNotAllowed,
            nameof(AgentIdentityError.BodyTooLarge) => AgentIdentityError.BodyTooLarge,
            nameof(AgentIdentityError.UnexpectedFailure) => AgentIdentityError.UnexpectedFailure,
            nameof(AgentIdentityError.ServiceUnavailable) => AgentIdentityError.ServiceUnavailable,
            _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Not a framework-level error."),
        };
    }
}
