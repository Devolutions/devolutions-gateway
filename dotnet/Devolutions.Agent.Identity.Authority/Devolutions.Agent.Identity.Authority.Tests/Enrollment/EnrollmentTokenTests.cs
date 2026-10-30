using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;

namespace Devolutions.Agent.Identity.Authority.Tests;

public class EnrollmentTokenTests
{
    // The bytes 00 to 1F, and their base64url encoding without padding (RFC 4648 §5).
    private static readonly byte[] SecretBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];
    private const string SecretText = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    // `<prefix>.<bag>.<secret>`, where `secret` is base64url of 32 random bytes.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [Fact]
    public void CreateEncodesTheGeneratorBytesAsTheSecret()
    {
        EnrollmentToken token =
            EnrollmentToken.Create("https://host/dvls", new ScriptedRandomNumberGenerator(SecretBytes));

        Assert.StartsWith("dvaet1.", token.Value, StringComparison.Ordinal);
        Assert.EndsWith("." + SecretText, token.Value, StringComparison.Ordinal);
    }

    // The authority stores the SHA-256 of the 32 bytes the secret encodes, not of its text.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [Fact]
    public void SecretHashIsTheSha256OfTheSecretBytes()
    {
        EnrollmentToken token =
            EnrollmentToken.Create("https://host/dvls", new ScriptedRandomNumberGenerator(SecretBytes));

        Assert.Equal(SHA256.HashData(SecretBytes), token.SecretHash.ToArray());
    }

    // A complete `dvaet1` token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`,
    // and its secret is the canonical base64url encoding of the 32 random bytes.
    // The random values are seeded, so a failure reproduces.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void CreateWritesEverySecretInTheContractPattern()
    {
        Random random = new(2);

        for (int i = 0; i < 256; i++)
        {
            byte[] bytes = new byte[32];
            random.NextBytes(bytes);

            EnrollmentToken token =
                EnrollmentToken.Create("https://host/dvls", new ScriptedRandomNumberGenerator(bytes));

            Assert.Matches(@"\Advaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}\z", token.Value);
            string secret = token.Value.Split('.')[2];
            Assert.Equal(bytes, Base64Url.DecodeFromChars(secret));
            Assert.Equal(secret, Base64Url.EncodeToString(bytes));
        }
    }

    // The authority stores SecretHash when it creates a token,
    // and finds the token of an enroll request by the hash that ReadBearerToken returns.
    // Both are the SHA-256 of the 32 bytes the token's secret encodes.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Fact]
    public void ReadBearerTokenReturnsTheSecretHashOfEveryCreatedToken()
    {
        Random random = new(3);

        foreach (string productBaseUrl in (string[])["https://host/dvls", UrlOfLength(3025)])
        {
            for (int i = 0; i < 64; i++)
            {
                byte[] bytes = new byte[32];
                random.NextBytes(bytes);
                EnrollmentToken token =
                    EnrollmentToken.Create(productBaseUrl, new ScriptedRandomNumberGenerator(bytes));
                byte[] expected = SHA256.HashData(bytes);

                EnrollmentAuthorizationResult result =
                    EnrollmentAuthorization.ReadBearerToken(["Bearer " + token.Value]);

                Assert.True(result.Succeeded);
                Assert.Equal(expected, token.SecretHash.ToArray());
                Assert.Equal(expected, result.SecretHash.ToArray());
            }
        }
    }

    // `bag` is the base64url encoding of a UTF-8 JSON object whose `u` is the product base URL,
    // so a URL already in the form of `u` is written as given.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [Theory]
    [InlineData("https://host/dvls")]
    [InlineData("https://host")]
    public void CreatePutsTheProductBaseUrlInTheBag(string productBaseUrl)
    {
        EnrollmentToken token = EnrollmentToken.Create(productBaseUrl, new ScriptedRandomNumberGenerator(SecretBytes));

        // The bag of a token the library creates holds `u` alone.
        // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Enrollment tokens
        Assert.Equal(("u", productBaseUrl), Assert.Single(BagMembers(token)));
    }

    // The authority keeps the token's `u` to compare it with the enrollment URL of each CSR the token presents
    // (CONTRACT.agent-identity.md §2.1), so ProductBaseUrl is the `u` that the bag holds: `https://host/dvls` for each
    // row, since `u` has no trailing slash and white space around a URI is not part of it (RFC 3986 Appendix C).
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [Theory]
    [InlineData("https://host/dvls")]
    [InlineData("https://host/dvls/")]
    [InlineData(" https://host/dvls\t")]
    public void ProductBaseUrlIsTheUOfTheBag(string productBaseUrl)
    {
        EnrollmentToken token = EnrollmentToken.Create(productBaseUrl, new ScriptedRandomNumberGenerator(SecretBytes));

        Assert.Equal("https://host/dvls", token.ProductBaseUrl);
        Assert.Equal(token.ProductBaseUrl, Assert.Single(BagMembers(token), member => member.Name == "u").Value);
    }

    // Create may reject a URL that is not in the form of `u`,
    // but a token it creates holds in `u` the form that the source of the row decides.
    [Theory]
    // `u` has no trailing slash, and the agent removes trailing slashes, so `https://host/` names `https://host`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [InlineData("https://host/dvls/", "https://host/dvls")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [InlineData("https://host/dvls//", "https://host/dvls")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    [InlineData("https://host/", "https://host")]
    // White space around a URI is not part of it.
    // oracle: spec RFC 3986 §Appendix C
    [InlineData(" https://host/dvls\t", "https://host/dvls")]
    public void CreateRejectsOrNormalizesAUrlNotInTheFormOfU(string productBaseUrl, string normalized)
    {
        Creation creation = CreateFrom(productBaseUrl);

        Assert.Contains(creation, (Creation[])[Creation.Holding(normalized), Creation.Rejection]);
    }

    // The unacceptable URLs, and a URL one byte longer than the longest that fits in a token.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    public static TheoryData<string> RejectedUrlRows => new(
    [
        .. UnacceptableUrls.All,
        UrlOfLength(3026),
    ]);

    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [MemberData(nameof(RejectedUrlRows))]
    public void CreateRejectsAnotherUrl(string productBaseUrl)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EnrollmentToken.Create(productBaseUrl, new ScriptedRandomNumberGenerator(SecretBytes)));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    // CONTRACT.agent-identity.md §2: a token is at most 4096 bytes.
    // A token's bag holds `u` alone, without insignificant white space, which fixes the longest URL that fits.
    // A 3025-byte URL makes a 3033-byte bag object, a 4044-character bag and a 4095-byte token.
    // One more byte makes a 4046-character bag and a 4097-byte token, since no base64url text has 4045 characters.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Enrollment tokens
    [Fact]
    public void CreateAcceptsTheLongestUrlThatFits()
    {
        EnrollmentToken token =
            EnrollmentToken.Create(UrlOfLength(3025), new ScriptedRandomNumberGenerator(SecretBytes));

        Assert.Equal(4095, token.Value.Length);
    }

    // Security invariant 9: tokens never appear in logs, not even partially,
    // and a log statement may format the token object.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Fact]
    public void ToStringRevealsNoPartOfTheToken()
    {
        EnrollmentToken token =
            EnrollmentToken.Create("https://host/dvls", new ScriptedRandomNumberGenerator(SecretBytes));
        string[] segments = token.Value.Split('.');

        EnrollmentTokenAssert.RevealsNoPart(token.ToString(), segments[1], segments[2]);
    }

    // Security invariant 9: a host may log the exception of a failed creation.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Theory]
    [MemberData(nameof(RejectedUrlRows))]
    public void CreateFailureRevealsNoPartOfTheSecret(string productBaseUrl)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EnrollmentToken.Create(productBaseUrl, new ScriptedRandomNumberGenerator(SecretBytes)));

        EnrollmentTokenAssert.RevealsNoPart(exception.Message, SecretText);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData("productBaseUrl")]
    [InlineData("randomNumberGenerator")]
    public void CreateRejectsANullArgument(string parameter)
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(CreationsWithANullArgument[parameter]);

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal(parameter, exception.ParamName);
    }

    // A creation with one null argument, by the name of the parameter that receives it.
    private static Dictionary<string, Action> CreationsWithANullArgument => new()
    {
        ["productBaseUrl"] = () => EnrollmentToken.Create(null!, new ScriptedRandomNumberGenerator(SecretBytes)),
        ["randomNumberGenerator"] = () => EnrollmentToken.Create("https://host/dvls", null!),
    };

    private static string UrlOfLength(int length)
    {
        const string prefix = "https://host/";

        return prefix + new string('a', length - prefix.Length);
    }

    // What Create makes of the URL: the `u` that the bag of its token holds, or a rejection.
    private static Creation CreateFrom(string productBaseUrl)
    {
        EnrollmentToken token;

        try
        {
            token = EnrollmentToken.Create(productBaseUrl, new ScriptedRandomNumberGenerator(SecretBytes));
        }
        catch (ArgumentException)
        {
            return Creation.Rejection;
        }

        return Creation.Holding(Assert.Single(BagMembers(token), member => member.Name == "u").Value);
    }

    // Reads the members of the bag, after checking that the bag is the canonical base64url encoding of its bytes.
    private static (string Name, string? Value)[] BagMembers(EnrollmentToken token)
    {
        string bag = token.Value.Split('.')[1];
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        Assert.True(Base64Url.IsValid(bag));
        byte[] json = Base64Url.DecodeFromChars(bag);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        Assert.Equal(bag, Base64Url.EncodeToString(json));

        using JsonDocument document = JsonDocument.Parse(json);

        return [.. document.RootElement.EnumerateObject().Select(member => (member.Name, member.Value.GetString()))];
    }

    // What Create makes of a URL: a rejection, or a token whose bag holds `U`.
    private sealed record Creation(bool Rejected, string? U)
    {
        public static Creation Rejection { get; } = new(Rejected: true, U: null);

        public static Creation Holding(string? u)
        {
            return new Creation(Rejected: false, U: u);
        }
    }
}
