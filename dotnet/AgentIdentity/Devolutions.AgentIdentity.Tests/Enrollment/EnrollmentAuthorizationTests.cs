using System.Security.Cryptography;
using System.Text;

namespace Devolutions.AgentIdentity.Tests;

public class EnrollmentAuthorizationTests
{
    // A token for https://host/dvls whose secret encodes the bytes 00 to 1F (CONTRACT.agent-identity.md §2).
    private const string Bag = "eyJ1IjoiaHR0cHM6Ly9ob3N0L2R2bHMifQ";
    private const string Secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    private const string Token = "dvaet1." + Bag + "." + Secret;

    public static TheoryData<string> FieldLinesWithoutABearerTokenNames => new(FieldLinesWithoutABearerToken.Keys);

    // Field lines that hold no bearer token, by what is wrong with them.
    private static Dictionary<string, string[]> FieldLinesWithoutABearerToken
    {
        get
        {
            Dictionary<string, string[]> fieldLines = new()
            {
                // (1): `token_invalid` when the `Authorization` header is missing.
                // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
                ["no field"] = [],

                // (1): `token_invalid` when the `Authorization` header is repeated,
                // even when every field line holds the same valid token.
                // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
                ["the same token twice"] = ["Bearer " + Token, "Bearer " + Token],
                ["a token, then an empty field"] = ["Bearer " + Token, ""],
                ["an empty field, then a token"] = ["", "Bearer " + Token],

                // (1): `token_invalid` when the `Authorization` header is not `Bearer`.
                // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
                ["Basic"] = ["Basic " + Token],
                ["DPoP"] = ["DPoP " + Token],
                ["Bearers"] = ["Bearers " + Token],
                ["Bear"] = ["Bear " + Token],
                ["no scheme"] = [Token],

                // One or more spaces, and nothing else, separate the scheme from the token.
                // oracle: spec RFC 9110 §11.4
                ["the scheme alone"] = ["Bearer"],
                ["the scheme and a space"] = ["Bearer "],
                ["no space"] = ["Bearer" + Token],
                ["a tab"] = ["Bearer\t" + Token],
                ["a space and a tab"] = ["Bearer \t" + Token],
            };

            // (1): a field that holds no token gets `token_invalid`.
            // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
            foreach ((string name, string token) in MalformedTokens)
            {
                fieldLines.Add(name, ["Bearer " + token]);
            }

            return fieldLines;
        }
    }

    // A complete `dvaet1` token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`.
    // The pattern covers the whole value, so a line terminator after the token is not part of a match.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    private static Dictionary<string, string> MalformedTokens => new()
    {
        ["another version"] = "dvaet2." + Bag + "." + Secret,
        ["an uppercase prefix"] = "DVAET1." + Bag + "." + Secret,
        ["no dot after the prefix"] = "dvaet1" + Bag + "." + Secret,
        ["no prefix"] = Bag + "." + Secret,
        ["an empty bag"] = "dvaet1.." + Secret,
        ["a padded bag"] = "dvaet1." + Bag + "=." + Secret,
        ["base64 characters in the bag"] = "dvaet1." + Bag + "+/." + Secret,
        ["a space in the bag"] = "dvaet1." + Bag + " ." + Secret,
        ["a fullwidth letter in the bag"] = "dvaet1." + Bag + "\uFF41." + Secret,
        ["a third dot"] = "dvaet1." + Bag + "." + Bag + "." + Secret,
        ["no secret"] = "dvaet1." + Bag,
        ["an empty secret"] = "dvaet1." + Bag + ".",
        ["a 42-character secret"] = "dvaet1." + Bag + "." + Secret[..42],
        ["a 44-character secret"] = "dvaet1." + Bag + "." + Secret + "A",
        ["a padded secret"] = "dvaet1." + Bag + "." + Secret[..42] + "=",
        ["a base64 character in the secret"] = "dvaet1." + Bag + "." + Secret[..42] + "/",
        ["a line feed after the token"] = Token + "\n",
        ["a CRLF after the token"] = Token + "\r\n",
        ["a NUL after the token"] = Token + "\0",
        ["a comma after the token"] = Token + ",",
        ["a second credential after the token"] = Token + ", Bearer " + Token,
    };

    // CONTRACT.agent-identity.md §2.1: the authority finds the token whose SHA-256(secret) matches,
    // and §2 makes it match the secret text exactly.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    [Theory]
    [InlineData("a bearer token", "Bearer " + Token)]
    // The authentication scheme is case-insensitive.
    // oracle: spec RFC 9110 §11.1
    [InlineData("a lowercase scheme", "bearer " + Token)]
    [InlineData("an uppercase scheme", "BEARER " + Token)]
    [InlineData("a mixed-case scheme", "bEaReR " + Token)]
    // `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`.
    // oracle: spec RFC 9110 §11.4
    [InlineData("two spaces", "Bearer  " + Token)]
    [InlineData("three spaces", "Bearer   " + Token)]
    // CONTRACT.agent-identity.md §2.1 (1): the authority finds a token by `SHA-256(secret)` alone,
    // and §2 makes the bag routing data that the authority never trusts, so it is not decoded.
    // The rows are a bag of an impossible base64url length, one that decodes to bytes that are not JSON,
    // and the bag of {"u":"https://other/psu"}.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    [InlineData("a one-character bag", "Bearer dvaet1.A." + Secret)]
    [InlineData("a bag that is not JSON", "Bearer dvaet1._-_-." + Secret)]
    [InlineData("the bag of another URL", "Bearer dvaet1.eyJ1IjoiaHR0cHM6Ly9vdGhlci9wc3UifQ." + Secret)]
    // A field value excludes the white space around it, which a parser removes before evaluating the value.
    // oracle: spec RFC 9110 §5.5
    [InlineData("a space before", " Bearer " + Token)]
    [InlineData("a space after", "Bearer " + Token + " ")]
    [InlineData("tabs around", "\tBearer " + Token + "\t")]
    [InlineData("spaces and tabs around", " \t Bearer " + Token + " \t ")]
    public void ReadsTheSecretHashOfABearerToken(string name, string fieldValue)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([fieldValue]);

        Assert.True(result.Succeeded, name);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
    [Theory]
    [MemberData(nameof(FieldLinesWithoutABearerTokenNames))]
    public void RejectsFieldLinesWithoutABearerToken(string fieldLines)
    {
        EnrollmentAuthorizationResult result =
            EnrollmentAuthorization.ReadBearerToken(FieldLinesWithoutABearerToken[fieldLines]);

        AssertTokenInvalid(result);
    }

    // A token is at most 4096 bytes.
    // The bag is not decoded, so a bag of any length in the alphabet sets the token length.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    [Fact]
    public void AcceptsATokenOf4096Bytes()
    {
        string token = "dvaet1." + new string('A', 4045) + "." + Secret;

        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + token]);

        Assert.Equal(4096, token.Length);
        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    // CONTRACT.agent-identity.md §2: a token is at most 4096 bytes;
    // §2.1 (1): a field that holds no token gets `token_invalid`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
    [Fact]
    public void RejectsATokenLongerThan4096Bytes()
    {
        string token = "dvaet1." + new string('A', 4046) + "." + Secret;

        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + token]);

        Assert.Equal(4097, token.Length);
        AssertTokenInvalid(result);
    }

    // The authority matches the `secret` text exactly.
    // Ending in '9' (sextet 61) instead of '8' (sextet 60) sets a pad bit,
    // so a lenient decoder reads the same 32 bytes, but the text, and so its hash, differs.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
    [Fact]
    public void HashesANonCanonicalSecretAsItsText()
    {
        string nonCanonical = Secret[..42] + "9";

        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(
            ["Bearer dvaet1." + Bag + "." + nonCanonical]);

        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(nonCanonical), result.SecretHash.ToArray());
        Assert.NotEqual(HashOf(Secret), result.SecretHash.ToArray());
    }

    // INTENT.agent-identity.md, security invariant 9: tokens never appear in logs, not even partially,
    // and a host logs the failure detail, the error and the result of a refused enrollment.
    // Each row takes another failure path with the token's bag and secret in the field.
    public static TheoryData<string[]> RefusedFieldLines => new()
    {
        Array.Empty<string>(),
        new[] { "Bearer " + Token, "Bearer " + Token },
        new[] { "Basic " + Token },
        new[] { Token },
        new[] { "Bearer" + Token },
        new[] { "Bearer" },
        new[] { "Bearer dvaet1." + Bag + new string('A', 4012) + "." + Secret },
        new[] { "Bearer " + Token + "\n" },
    };

    // Security invariant 9: tokens never appear in logs, not even partially.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Theory]
    [MemberData(nameof(RefusedFieldLines))]
    public void FailureRevealsNoPartOfTheToken(string[] fieldLines)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(fieldLines);

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
        Assert.False(result.Succeeded);
        EnrollmentTokenAssert.RevealsNoPart(result.FailureDetail, Bag, Secret);
        EnrollmentTokenAssert.RevealsNoPart(result.Error.Message, Bag, Secret);
        EnrollmentTokenAssert.RevealsNoPart($"{result}", Bag, Secret);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void RejectsNullFieldLines()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentAuthorization.ReadBearerToken(null!));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("authorizationFieldLines", exception.ParamName);
    }

    // CONTRACT.agent-identity.md §5.4: `token_invalid` is carried by HTTP 401.
    private static void AssertTokenInvalid(EnrollmentAuthorizationResult result)
    {
        Assert.False(result.Succeeded);
        Assert.Equal(AgentIdentityErrorCode.TokenInvalid, result.Error.Code);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-errors
        Assert.Equal(401, result.Error.HttpStatusCode);
    }

    private static byte[] HashOf(string secret)
    {
        return SHA256.HashData(Encoding.ASCII.GetBytes(secret));
    }
}
