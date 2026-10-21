using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Devolutions.AgentIdentity.Tests;

public class EnrollmentTokenTests
{
    // The bytes 00 to 1F, and their base64url encoding without padding (RFC 4648 §5).
    private static readonly byte[] SecretBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];
    private const string SecretText = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    // `<prefix>.<bag>.<secret>`, where `secret` is base64url of 32 random bytes.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    [Fact]
    public void CreateEncodesTheGeneratorBytesAsTheSecret()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));

        Assert.StartsWith("dvaet1.", token.Value, StringComparison.Ordinal);
        Assert.EndsWith("." + SecretText, token.Value, StringComparison.Ordinal);
    }

    // The authority matches the `secret` text exactly,
    // so it hashes the 43 characters rather than the bytes they encode.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
    [Fact]
    public void SecretHashIsTheSha256OfTheSecretText()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));

        Assert.Equal(SHA256.HashData(Encoding.ASCII.GetBytes(SecretText)), token.SecretHash.ToArray());
    }

    // A complete `dvaet1` token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`,
    // and its secret is the canonical base64url encoding of the 32 random bytes.
    // The random values are seeded, so a failure reproduces.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [Fact]
    public void CreateWritesEverySecretInTheContractPattern()
    {
        Random random = new(2);

        for (int i = 0; i < 256; i++)
        {
            byte[] bytes = new byte[32];
            random.NextBytes(bytes);

            EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(bytes));

            Assert.Matches(@"\Advaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}\z", token.Value);
            string secret = token.Value.Split('.')[2];
            Assert.Equal(bytes, Base64Url.DecodeFromChars(secret));
            Assert.Equal(secret, Base64Url.EncodeToString(bytes));
        }
    }

    // The authority stores SecretHash when it creates a token,
    // and finds the token of an enroll request by the hash that ReadBearerToken returns.
    // CONTRACT.agent-identity.md §2: the authority matches the `secret` text exactly,
    // so both hashes are the SHA-256 of the 43 ASCII characters of the token's secret.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
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
                EnrollmentToken token = EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(bytes));
                byte[] expected = SHA256.HashData(Encoding.ASCII.GetBytes(token.Value.Split('.')[2]));

                EnrollmentAuthorizationResult result =
                    EnrollmentAuthorization.ReadBearerToken(["Bearer " + token.Value]);

                Assert.True(result.Succeeded);
                Assert.Equal(expected, token.SecretHash.ToArray());
                Assert.Equal(expected, result.SecretHash.ToArray());
            }
        }
    }

    // `bag` is the base64url encoding of a UTF-8 JSON object whose `u` is the product base URL.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    [Theory]
    [InlineData("https://host/dvls", "https://host/dvls")]
    // The agent appends `/api/agent-identity/v1/...` to `u` (CONTRACT.agent-identity.md §5),
    // so `u` ends without a slash.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5
    [InlineData("https://host/dvls/", "https://host/dvls")]
    [InlineData("https://host/dvls//", "https://host/dvls")]
    [InlineData("https://host/", "https://host")]
    [InlineData("https://host", "https://host")]
    // A URI holds no white space (RFC 3986 §2):
    // white space around it is not part of it (Appendix C),
    // and a space or a non-ASCII character inside it is percent-encoded (§2.1; RFC 3987 §3.1).
    // oracle: spec RFC 3986 §Appendix C
    [InlineData(" https://host/dvls\t", "https://host/dvls")]
    // oracle: spec RFC 3986 §2.1
    [InlineData("https://host/my dvls", "https://host/my%20dvls")]
    // oracle: spec RFC 3987 §3.1
    [InlineData("https://host/dvls\u00E9", "https://host/dvls%C3%A9")]
    public void CreatePutsTheProductBaseUrlInTheBag(string productBaseUrl, string expected)
    {
        EnrollmentToken token = EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes));

        // The bag of a token the library creates holds `u` alone.
        // oracle: intent dotnet/AgentIdentity/INTENT.md §Enrollment tokens
        Assert.Equal(("u", expected), Assert.Single(BagMembers(token)));
    }

    // CONTRACT.agent-identity.md §2: `u` is an absolute `https` URL without a query or fragment.
    // RFC 9110 §4.2.4 deprecates user information in an `https` URI and tells a recipient to treat it as an error.
    private static readonly string[] UnacceptableUrls =
    [
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
        "",
        "/dvls",
        "host/dvls",
        "http://host/dvls",
        "wss://host/dvls",
        // oracle: spec RFC 9110 §4.2.2
        "https:///dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
        "https://host/dvls?tenant=1",
        "https://host/dvls?",
        "https://host/dvls#top",
        "https://host/dvls#",
        // oracle: spec RFC 9110 §4.2.4
        "https://admin@host/dvls",
        "https://@host/dvls",
    ];

    // The unacceptable URLs, and a URL one byte longer than the longest that fits in a token
    // (CONTRACT.agent-identity.md §2).
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    public static TheoryData<string> RejectedUrlRows => new([.. UnacceptableUrls, UrlOfLength(3026)]);

    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [MemberData(nameof(RejectedUrlRows))]
    public void CreateRejectsAnotherUrl(string productBaseUrl)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes)));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    // CONTRACT.agent-identity.md §2: a token is at most 4096 bytes.
    // A token's bag holds `u` alone, without insignificant white space, which fixes the longest URL that fits.
    // A 3025-byte URL makes a 3033-byte bag object, a 4044-character bag and a 4095-byte token.
    // One more byte makes a 4046-character bag and a 4097-byte token, since no base64url text has 4045 characters.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Enrollment tokens
    [Fact]
    public void CreateAcceptsTheLongestUrlThatFits()
    {
        EnrollmentToken token = EnrollmentToken.Create(UrlOfLength(3025), new ReplayingGenerator(SecretBytes));

        Assert.Equal(4095, token.Value.Length);
    }

    // Security invariant 9: tokens never appear in logs, not even partially,
    // and a log statement may format the token object.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Fact]
    public void ToStringRevealsNoPartOfTheToken()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));
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
            () => EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes)));

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
        ["productBaseUrl"] = () => EnrollmentToken.Create(null!, new ReplayingGenerator(SecretBytes)),
        ["randomNumberGenerator"] = () => EnrollmentToken.Create("https://host/dvls", null!),
    };

    private static string UrlOfLength(int length)
    {
        const string prefix = "https://host/";

        return prefix + new string('a', length - prefix.Length);
    }

    // Reads the members of the bag, after checking that the bag is the canonical base64url encoding of its bytes.
    private static (string Name, string? Value)[] BagMembers(EnrollmentToken token)
    {
        string bag = token.Value.Split('.')[1];
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-enrollment-token
        Assert.True(Base64Url.IsValid(bag));
        byte[] json = Base64Url.DecodeFromChars(bag);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
        Assert.Equal(bag, Base64Url.EncodeToString(json));

        using JsonDocument document = JsonDocument.Parse(json);

        return [.. document.RootElement.EnumerateObject().Select(member => (member.Name, member.Value.GetString()))];
    }

    /// <summary>
    /// A generator that returns the given bytes in order, so that a test knows the secret it produces.
    /// </summary>
    private sealed class ReplayingGenerator(byte[] bytes) : RandomNumberGenerator
    {
        private int _position;

        public override void GetBytes(byte[] data)
        {
            GetBytes(data.AsSpan());
        }

        public override void GetBytes(Span<byte> data)
        {
            bytes.AsSpan(_position, data.Length).CopyTo(data);
            _position += data.Length;
        }
    }
}
