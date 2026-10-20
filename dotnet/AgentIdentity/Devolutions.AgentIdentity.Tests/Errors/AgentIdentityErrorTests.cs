using System.Text.Json;
using Grpc.Core;

namespace Devolutions.AgentIdentity.Tests;

public class AgentIdentityErrorTests
{
    // 12:00:00.750 UTC given in a +02:00 offset, which CONTRACT.md §1 writes as a UTC timestamp in whole seconds.
    private static readonly DateTimeOffset ServerTime =
        new DateTimeOffset(2026, 9, 24, 14, 0, 0, TimeSpan.FromHours(2)).AddMilliseconds(750);

    private const string ServerTimeText = "2026-09-24T12:00:00Z";

    // CONTRACT.md §5.4, column "HTTP".
    [Theory]
    [MemberData(nameof(AgentIdentityErrorCodeTests.HttpStatusCodes), MemberType = typeof(AgentIdentityErrorCodeTests))]
    public void FromCarriesTheCodeWithItsContractStatus(AgentIdentityErrorCode code, int expectedStatus)
    {
        AgentIdentityError error = AgentIdentityError.From(code);

        Assert.Equal(code, error.Code);
        Assert.Equal(expectedStatus, error.HttpStatusCode);
    }

    [Fact]
    public void FromRejectsAnUndefinedCode()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AgentIdentityError.From(default));
    }

    // CONTRACT.md §5.4: malformed JSON or body → 400 invalid_request; unknown route → 404 invalid_request;
    // wrong method → 405 invalid_request; body too large → 413 invalid_request;
    // an unexpected server failure → 500 unavailable; overload or a missing dependency → 503 unavailable.
    [Theory]
    [InlineData(nameof(AgentIdentityError.MalformedBody), 400, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(nameof(AgentIdentityError.UnknownRoute), 404, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(nameof(AgentIdentityError.MethodNotAllowed), 405, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(nameof(AgentIdentityError.BodyTooLarge), 413, AgentIdentityErrorCode.InvalidRequest)]
    [InlineData(nameof(AgentIdentityError.UnexpectedFailure), 500, AgentIdentityErrorCode.Unavailable)]
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

    // CONTRACT.md §5.4 body, with the snake_case keys and the timestamp format of §1.
    // Parsing the raw bytes also rejects a byte order mark, which RFC 8259 §8.1 forbids in a JSON text.
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

    // CONTRACT.md §7.4: a refused channel opening carries the code's status.
    // §7.3 step 4: invalid `Hello` metadata gets INVALID_ARGUMENT.
    [Theory]
    [InlineData(AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated)]
    [InlineData(AgentIdentityErrorCode.IdentityRevoked, StatusCode.PermissionDenied)]
    [InlineData(AgentIdentityErrorCode.InvalidRequest, StatusCode.InvalidArgument)]
    [InlineData(AgentIdentityErrorCode.Unavailable, StatusCode.Unavailable)]
    public void RpcExceptionHasTheChannelStatus(AgentIdentityErrorCode code, StatusCode expected)
    {
        RpcException exception = AgentIdentityError.From(code).ToRpcException(ServerTime);

        Assert.Equal(expected, exception.StatusCode);
    }

    // CONTRACT.md §7.4: trailers `error-code: <§5.4 code>` and `server-time: <RFC 3339>`.
    [Fact]
    public void RpcExceptionHasExactlyTheContractTrailers()
    {
        RpcException exception = AgentIdentityError.From(AgentIdentityErrorCode.ClockSkew).ToRpcException(ServerTime);

        Assert.Equal(
            [("error-code", "clock_skew"), ("server-time", ServerTimeText)],
            exception.Trailers.Select(entry => (entry.Key, entry.Value)));
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
