using System.Text;

namespace Devolutions.Agent.Identity.Authority.Tests;

public class ConfirmRequestBodyTests
{
    // A token for https://host/dvls whose secret encodes the bytes 00 to 1F (CONTRACT.agent-identity.md §2).
    private const string Bag = "eyJ1IjoiaHR0cHM6Ly9ob3N0L2R2bHMifQ";
    private const string Secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    // A confirm request carries no body.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §confirm
    [Fact]
    public void AcceptsEmptyBody()
    {
        RequestBodyParseResult<ConfirmRequestBody> result = ConfirmRequestBody.Parse([]);

        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Null(result.Error);
    }

    // A body holding only white space, a byte order mark, an empty JSON object or a NUL byte is not empty.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §confirm
    [Theory]
    [InlineData("empty JSON object", "{}")]
    [InlineData("JSON null", "null")]
    [InlineData("space", " ")]
    [InlineData("line break", "\r\n")]
    [InlineData("byte order mark", "\uFEFF")]
    [InlineData("NUL byte", "\0")]
    public void RejectsNonEmptyBody(string form, string body)
    {
        RequestBodyParseResult<ConfirmRequestBody> result = ConfirmRequestBody.Parse(Encoding.UTF8.GetBytes(body));

        Assert.False(result.Succeeded, form);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, result.Error.Code);
    }

    // Invariant 9: tokens never appear in logs, not even partially,
    // and a host logs the failure detail and the error of a rejected body, whatever the body holds.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Fact]
    public void FailureRevealsNoPartOfATokenInTheBody()
    {
        byte[] body = Encoding.UTF8.GetBytes("dvaet1." + Bag + "." + Secret);

        RequestBodyParseResult<ConfirmRequestBody> result = ConfirmRequestBody.Parse(body);

        Assert.False(result.Succeeded);
        EnrollmentTokenAssert.RevealsNoPart(result.FailureDetail, Bag, Secret);
        EnrollmentTokenAssert.RevealsNoPart(result.Error.Message, Bag, Secret);
    }
}
