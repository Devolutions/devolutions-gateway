using Grpc.Core;

namespace Devolutions.AgentIdentity.Tests;

public class AgentIdentityErrorCodeTests
{
    // CONTRACT.agent-identity.md §5.4, column "Code".
    public static TheoryData<AgentIdentityErrorCode, string> WireValues => new()
    {
        { AgentIdentityErrorCode.TokenInvalid, "token_invalid" },
        { AgentIdentityErrorCode.TokenExhausted, "token_exhausted" },
        { AgentIdentityErrorCode.TokenExpired, "token_expired" },
        { AgentIdentityErrorCode.IdentityRevoked, "identity_revoked" },
        { AgentIdentityErrorCode.IdentityUnknown, "identity_unknown" },
        { AgentIdentityErrorCode.CertificateExpired, "certificate_expired" },
        { AgentIdentityErrorCode.SignatureInvalid, "signature_invalid" },
        { AgentIdentityErrorCode.ClockSkew, "clock_skew" },
        { AgentIdentityErrorCode.InvalidRequest, "invalid_request" },
        { AgentIdentityErrorCode.Unavailable, "unavailable" },
    };

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [Theory]
    [MemberData(nameof(WireValues))]
    public void WireValueIsTheContractCode(AgentIdentityErrorCode code, string expected)
    {
        Assert.Equal(expected, code.ToWireValue());
    }

    // CONTRACT.agent-identity.md §5.4, column "HTTP", for the codes to which it gives one status.
    public static TheoryData<AgentIdentityErrorCode, int> HttpStatusCodes => new()
    {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.TokenInvalid, 401 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.TokenExhausted, 403 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.TokenExpired, 401 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.IdentityRevoked, 403 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.IdentityUnknown, 401 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.CertificateExpired, 401 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.SignatureInvalid, 401 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.ClockSkew, 401 },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.InvalidRequest, 400 },
    };

    // CONTRACT.agent-identity.md §5.4, column "HTTP", for the codes to which it gives a class of statuses,
    // with the lowest and the highest status of the class: `unavailable` is 5xx.
    public static TheoryData<AgentIdentityErrorCode, int, int> HttpStatusClasses => new()
    {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        { AgentIdentityErrorCode.Unavailable, 500, 599 },
    };

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [Theory]
    [MemberData(nameof(HttpStatusCodes))]
    public void HttpStatusCodeIsTheContractStatus(AgentIdentityErrorCode code, int expected)
    {
        Assert.Equal(expected, code.ToHttpStatusCode());
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [Theory]
    [MemberData(nameof(HttpStatusClasses))]
    public void HttpStatusCodeIsInTheContractClass(AgentIdentityErrorCode code, int lowest, int highest)
    {
        Assert.InRange(code.ToHttpStatusCode(), lowest, highest);
    }

    // CONTRACT.agent-identity.md §7.4: an authentication failure closes the stream with UNAUTHENTICATED,
    // or PERMISSION_DENIED for `identity_revoked`.
    // §7.3 step 4: invalid `Hello` metadata closes it with INVALID_ARGUMENT and `invalid_request`.
    // §7.4: so does a message that cannot be decoded on an authenticated stream.
    // `unavailable` gets UNAVAILABLE, which gRPC defines as a transient condition.
    public static TheoryData<AgentIdentityErrorCode, StatusCode> GrpcStatusCodes => new()
    {
        // oracle: mutant the gRPC mapping throws for token_invalid as for an undefined code
        { AgentIdentityErrorCode.TokenInvalid, StatusCode.Unauthenticated },
        // oracle: mutant the gRPC mapping throws for token_exhausted as for an undefined code
        { AgentIdentityErrorCode.TokenExhausted, StatusCode.Unauthenticated },
        // oracle: mutant the gRPC mapping throws for token_expired as for an undefined code
        { AgentIdentityErrorCode.TokenExpired, StatusCode.Unauthenticated },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        { AgentIdentityErrorCode.IdentityRevoked, StatusCode.PermissionDenied },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        { AgentIdentityErrorCode.IdentityUnknown, StatusCode.Unauthenticated },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        { AgentIdentityErrorCode.CertificateExpired, StatusCode.Unauthenticated },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        { AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        { AgentIdentityErrorCode.ClockSkew, StatusCode.Unauthenticated },
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        { AgentIdentityErrorCode.InvalidRequest, StatusCode.InvalidArgument },
        // oracle: spec gRPC status codes §Status codes and their use in gRPC
        { AgentIdentityErrorCode.Unavailable, StatusCode.Unavailable },
    };

    // Most rows follow the closures of the channel; each row's marker names the source that decides it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    [Theory]
    [MemberData(nameof(GrpcStatusCodes))]
    public void GrpcStatusCodeIsTheContractStatus(AgentIdentityErrorCode code, StatusCode expected)
    {
        Assert.Equal(expected, code.ToGrpcStatusCode());
    }

    // CONTRACT.agent-identity.md §5.4 lists exactly these ten codes.
    // A code added without a contract row would otherwise go untested in every table above.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    [Fact]
    public void EveryCodeHasAContractRow()
    {
        AgentIdentityErrorCode[] defined = Enum.GetValues<AgentIdentityErrorCode>();

        Assert.Equal(defined, CodesOf(WireValues));
        Assert.Equal(defined, CodesOf(HttpStatusCodes).Concat(CodesOf(HttpStatusClasses)).Order());
        Assert.Equal(defined, CodesOf(GrpcStatusCodes));
    }

    // The default value of the enum is not a code, so a mapping must not turn it into one.
    // Framework Design Guidelines, Parameter Design: validate enum parameters, since an enum may hold any integer.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Fact]
    public void UndefinedCodeHasNoMapping()
    {
        AgentIdentityErrorCode undefined = default;

        Assert.Throws<ArgumentOutOfRangeException>(() => undefined.ToWireValue());
        Assert.Throws<ArgumentOutOfRangeException>(() => undefined.ToHttpStatusCode());
        Assert.Throws<ArgumentOutOfRangeException>(() => undefined.ToGrpcStatusCode());
    }

    private static IEnumerable<AgentIdentityErrorCode> CodesOf(IEnumerable<object[]> rows)
    {
        return rows.Select(row => (AgentIdentityErrorCode)row[0]).Order();
    }
}
