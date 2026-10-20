using Grpc.Core;

namespace Devolutions.AgentIdentity.Tests;

public class AgentIdentityErrorCodeTests
{
    // CONTRACT.md §5.4, column "Code".
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

    [Theory]
    [MemberData(nameof(WireValues))]
    public void WireValueIsTheContractCode(AgentIdentityErrorCode code, string expected)
    {
        Assert.Equal(expected, code.ToWireValue());
    }

    // CONTRACT.md §5.4, column "HTTP".
    // The table gives `unavailable` 5xx, and an unexpected failure gets 500.
    public static TheoryData<AgentIdentityErrorCode, int> HttpStatusCodes => new()
    {
        { AgentIdentityErrorCode.TokenInvalid, 401 },
        { AgentIdentityErrorCode.TokenExhausted, 403 },
        { AgentIdentityErrorCode.TokenExpired, 401 },
        { AgentIdentityErrorCode.IdentityRevoked, 403 },
        { AgentIdentityErrorCode.IdentityUnknown, 401 },
        { AgentIdentityErrorCode.CertificateExpired, 401 },
        { AgentIdentityErrorCode.SignatureInvalid, 401 },
        { AgentIdentityErrorCode.ClockSkew, 401 },
        { AgentIdentityErrorCode.InvalidRequest, 400 },
        { AgentIdentityErrorCode.Unavailable, 500 },
    };

    [Theory]
    [MemberData(nameof(HttpStatusCodes))]
    public void HttpStatusCodeIsTheContractStatus(AgentIdentityErrorCode code, int expected)
    {
        Assert.Equal(expected, code.ToHttpStatusCode());
    }

    // CONTRACT.md §7.4: an authentication failure closes the stream with UNAUTHENTICATED,
    // or PERMISSION_DENIED for `identity_revoked`.
    // §7.3 step 4: invalid `Hello` metadata closes it with INVALID_ARGUMENT and `invalid_request`.
    // `unavailable` gets UNAVAILABLE, which gRPC defines as a transient condition.
    public static TheoryData<AgentIdentityErrorCode, StatusCode> GrpcStatusCodes => new()
    {
        { AgentIdentityErrorCode.TokenInvalid, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.TokenExhausted, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.TokenExpired, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.IdentityRevoked, StatusCode.PermissionDenied },
        { AgentIdentityErrorCode.IdentityUnknown, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.CertificateExpired, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.SignatureInvalid, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.ClockSkew, StatusCode.Unauthenticated },
        { AgentIdentityErrorCode.InvalidRequest, StatusCode.InvalidArgument },
        { AgentIdentityErrorCode.Unavailable, StatusCode.Unavailable },
    };

    [Theory]
    [MemberData(nameof(GrpcStatusCodes))]
    public void GrpcStatusCodeIsTheContractStatus(AgentIdentityErrorCode code, StatusCode expected)
    {
        Assert.Equal(expected, code.ToGrpcStatusCode());
    }

    // CONTRACT.md §5.4 lists exactly these ten codes.
    // A code added without a contract row would otherwise go untested in every table above.
    [Fact]
    public void EveryCodeHasAContractRow()
    {
        AgentIdentityErrorCode[] defined = Enum.GetValues<AgentIdentityErrorCode>();

        Assert.Equal(defined, CodesOf(WireValues));
        Assert.Equal(defined, CodesOf(HttpStatusCodes));
        Assert.Equal(defined, CodesOf(GrpcStatusCodes));
    }

    // The default value of the enum is not a code, so a mapping must not turn it into one.
    // Framework Design Guidelines, Parameter Design: validate enum parameters, since an enum may hold any integer.
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
