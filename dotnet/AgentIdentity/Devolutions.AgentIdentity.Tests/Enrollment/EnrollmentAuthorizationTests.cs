using System.Security.Cryptography;
using System.Text;

namespace Devolutions.AgentIdentity.Tests;

public class EnrollmentAuthorizationTests
{
    // A token for https://host/dvls whose secret encodes the bytes 00 to 1F (CONTRACT.md §2).
    private const string Bag = "eyJ1IjoiaHR0cHM6Ly9ob3N0L2R2bHMifQ";
    private const string Secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    private const string Token = "dvaet1." + Bag + "." + Secret;

    // CONTRACT.md §2.1: the authority finds the token whose SHA-256(secret) matches,
    // and §2 makes it match the secret text exactly.
    [Fact]
    public void ReadsTheSecretHashOfABearerToken()
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + Token]);

        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    // CONTRACT.md §2.1 (1): `token_invalid` when the `Authorization` header is missing.
    [Fact]
    public void RejectsARequestWithoutAuthorization()
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([]);

        AssertTokenInvalid(result);
    }

    // CONTRACT.md §2.1 (1): `token_invalid` when the `Authorization` header is repeated,
    // even when every field line holds the same valid token.
    [Theory]
    [InlineData("Bearer " + Token, "Bearer " + Token)]
    [InlineData("Bearer " + Token, "")]
    [InlineData("", "Bearer " + Token)]
    public void RejectsARepeatedAuthorizationField(string first, string second)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([first, second]);

        AssertTokenInvalid(result);
    }

    // RFC 9110 §11.1: the authentication scheme is case-insensitive.
    [Theory]
    [InlineData("bearer")]
    [InlineData("BEARER")]
    [InlineData("bEaReR")]
    public void AcceptsTheBearerSchemeInAnyCase(string scheme)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([scheme + " " + Token]);

        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    // CONTRACT.md §2.1 (1): `token_invalid` when the `Authorization` header is not `Bearer`.
    [Theory]
    [InlineData("Basic " + Token)]
    [InlineData("DPoP " + Token)]
    [InlineData("Bearers " + Token)]
    [InlineData("Bear " + Token)]
    [InlineData(Token)]
    public void RejectsAnotherScheme(string fieldValue)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([fieldValue]);

        AssertTokenInvalid(result);
    }

    // RFC 9110 §11.4: `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`.
    [Theory]
    [InlineData("Bearer  " + Token)]
    [InlineData("Bearer   " + Token)]
    public void AcceptsSeveralSpacesBeforeTheToken(string fieldValue)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([fieldValue]);

        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    // RFC 9110 §11.4: one or more spaces, and nothing else, separate the scheme from the token.
    [Theory]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("Bearer" + Token)]
    [InlineData("Bearer\t" + Token)]
    [InlineData("Bearer \t" + Token)]
    public void RejectsAFieldWithoutSpacesThenAToken(string fieldValue)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([fieldValue]);

        AssertTokenInvalid(result);
    }

    // CONTRACT.md §2: a complete `dvaet1` token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`;
    // §2.1 (1): a field that holds no token gets `token_invalid`.
    // The pattern covers the whole value, so a line terminator after the token is not part of a match.
    public static TheoryData<string> MalformedTokens => new()
    {
        "dvaet2." + Bag + "." + Secret,
        "DVAET1." + Bag + "." + Secret,
        "dvaet1" + Bag + "." + Secret,
        Bag + "." + Secret,
        "dvaet1.." + Secret,
        "dvaet1." + Bag + "=." + Secret,
        "dvaet1." + Bag + "+/." + Secret,
        "dvaet1." + Bag + " ." + Secret,
        "dvaet1." + Bag + "\uFF41." + Secret,
        "dvaet1." + Bag + "." + Bag + "." + Secret,
        "dvaet1." + Bag,
        "dvaet1." + Bag + ".",
        "dvaet1." + Bag + "." + Secret[..42],
        "dvaet1." + Bag + "." + Secret + "A",
        "dvaet1." + Bag + "." + Secret[..42] + "=",
        "dvaet1." + Bag + "." + Secret[..42] + "/",
        Token + "\n",
        Token + "\r\n",
        Token + "\0",
        Token + ",",
        Token + ", Bearer " + Token,
    };

    [Theory]
    [MemberData(nameof(MalformedTokens))]
    public void RejectsAValueThatIsNotADvaet1Token(string token)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + token]);

        AssertTokenInvalid(result);
    }

    // CONTRACT.md §2: a token is at most 4096 bytes.
    // The bag is not decoded, so a bag of any length in the alphabet sets the token length.
    [Fact]
    public void AcceptsATokenOf4096Bytes()
    {
        string token = "dvaet1." + new string('A', 4045) + "." + Secret;

        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + token]);

        Assert.Equal(4096, token.Length);
        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    [Fact]
    public void RejectsATokenLongerThan4096Bytes()
    {
        string token = "dvaet1." + new string('A', 4046) + "." + Secret;

        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + token]);

        Assert.Equal(4097, token.Length);
        AssertTokenInvalid(result);
    }

    // CONTRACT.md §2.1 (1): the authority finds a token by `SHA-256(secret)` alone,
    // and §2 makes the bag routing data that the authority never trusts, so it is not decoded.
    // The rows are a bag of an impossible base64url length, one that decodes to bytes that are not JSON,
    // and the bag of {"u":"https://other/psu"}.
    [Theory]
    [InlineData("A")]
    [InlineData("_-_-")]
    [InlineData("eyJ1IjoiaHR0cHM6Ly9vdGhlci9wc3UifQ")]
    public void ReadsTheSecretHashWhateverTheBag(string bag)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(
            ["Bearer dvaet1." + bag + "." + Secret]);

        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
    }

    // CONTRACT.md §2: the authority matches the `secret` text exactly.
    // Ending in '9' (sextet 61) instead of '8' (sextet 60) sets a pad bit,
    // so a lenient decoder reads the same 32 bytes, but the text, and so its hash, differs.
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

    // RFC 9110 §5.5: a field value excludes the white space around it,
    // which a parser removes before evaluating the value.
    [Theory]
    [InlineData(" Bearer " + Token)]
    [InlineData("Bearer " + Token + " ")]
    [InlineData("\tBearer " + Token + "\t")]
    [InlineData(" \t Bearer " + Token + " \t ")]
    public void IgnoresWhiteSpaceAroundTheFieldValue(string fieldValue)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken([fieldValue]);

        Assert.True(result.Succeeded);
        Assert.Equal(HashOf(Secret), result.SecretHash.ToArray());
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

    [Theory]
    [MemberData(nameof(RefusedFieldLines))]
    public void FailureRevealsNoPartOfTheToken(string[] fieldLines)
    {
        EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(fieldLines);

        Assert.False(result.Succeeded);
        EnrollmentTokenAssert.RevealsNoPart(result.FailureDetail, Bag, Secret);
        EnrollmentTokenAssert.RevealsNoPart(result.Error.Message, Bag, Secret);
        EnrollmentTokenAssert.RevealsNoPart($"{result}", Bag, Secret);
    }

    [Fact]
    public void RejectsNullFieldLines()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentAuthorization.ReadBearerToken(null!));

        Assert.Equal("authorizationFieldLines", exception.ParamName);
    }

    // CONTRACT.md §5.4: `token_invalid` is carried by HTTP 401.
    private static void AssertTokenInvalid(EnrollmentAuthorizationResult result)
    {
        Assert.False(result.Succeeded);
        Assert.Equal(AgentIdentityErrorCode.TokenInvalid, result.Error.Code);
        Assert.Equal(401, result.Error.HttpStatusCode);
    }

    private static byte[] HashOf(string secret)
    {
        return SHA256.HashData(Encoding.ASCII.GetBytes(secret));
    }
}
