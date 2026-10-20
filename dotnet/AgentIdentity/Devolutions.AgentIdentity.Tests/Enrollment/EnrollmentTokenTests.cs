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

    // CONTRACT.md §2: `<prefix>.<bag>.<secret>`, where `secret` is base64url of 32 random bytes.
    [Fact]
    public void CreateEncodesTheGeneratorBytesAsTheSecret()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));

        Assert.StartsWith("dvaet1.", token.Value, StringComparison.Ordinal);
        Assert.EndsWith("." + SecretText, token.Value, StringComparison.Ordinal);
    }

    // CONTRACT.md §2: the authority matches the `secret` text exactly,
    // so it hashes the 43 characters rather than the bytes they encode.
    [Fact]
    public void SecretHashIsTheSha256OfTheSecretText()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));

        Assert.Equal(SHA256.HashData(Encoding.ASCII.GetBytes(SecretText)), token.SecretHash.ToArray());
    }

    // CONTRACT.md §2: a complete `dvaet1` token matches `^dvaet1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`,
    // and its secret is the canonical base64url encoding of the 32 random bytes.
    // The random values are seeded, so a failure reproduces.
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

                EnrollmentAuthorizationResult result = EnrollmentAuthorization.ReadBearerToken(["Bearer " + token.Value]);

                Assert.True(result.Succeeded);
                Assert.Equal(token.SecretHash.ToArray(), result.SecretHash.ToArray());
            }
        }
    }

    // CONTRACT.md §2: `bag` is the base64url encoding of a UTF-8 JSON object whose `u` is the product base URL.
    [Fact]
    public void CreatePutsTheProductBaseUrlInTheBag()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));

        Assert.Equal(("u", "https://host/dvls"), Assert.Single(BagMembers(token)));
    }

    // The agent appends `/api/agent-identity/v1/...` to `u` (CONTRACT.md §5), so `u` ends without a slash.
    [Theory]
    [InlineData("https://host/dvls/", "https://host/dvls")]
    [InlineData("https://host/dvls//", "https://host/dvls")]
    [InlineData("https://host/", "https://host")]
    [InlineData("https://host", "https://host")]
    public void CreateRemovesTrailingSlashesFromTheUrl(string productBaseUrl, string expected)
    {
        EnrollmentToken token = EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes));

        Assert.Equal(("u", expected), Assert.Single(BagMembers(token)));
    }

    // CONTRACT.md §2: `u` is an absolute `https` URL without a query or fragment.
    // RFC 9110 §4.2.4 deprecates user information in an `https` URI and tells a recipient to treat it as an error.
    private static readonly string[] UnacceptableUrls =
    [
        "",
        "/dvls",
        "host/dvls",
        "http://host/dvls",
        "wss://host/dvls",
        "https:///dvls",
        "https://host/dvls?tenant=1",
        "https://host/dvls?",
        "https://host/dvls#top",
        "https://host/dvls#",
        "https://admin@host/dvls",
        "https://@host/dvls",
    ];

    public static TheoryData<string> UnacceptableUrlRows => new(UnacceptableUrls);

    [Theory]
    [MemberData(nameof(UnacceptableUrlRows))]
    public void CreateRejectsAnotherUrl(string productBaseUrl)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes)));

        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    // A URI holds no white space (RFC 3986 §2):
    // white space around it is not part of it (Appendix C),
    // and a space or a non-ASCII character inside it is percent-encoded (§2.1; RFC 3987 §3.1).
    [Theory]
    [InlineData(" https://host/dvls\t", "https://host/dvls")]
    [InlineData("https://host/my dvls", "https://host/my%20dvls")]
    [InlineData("https://host/dvls\u00E9", "https://host/dvls%C3%A9")]
    public void CreateWritesTheUrlInUriSyntax(string productBaseUrl, string expected)
    {
        EnrollmentToken token = EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes));

        Assert.Equal(("u", expected), Assert.Single(BagMembers(token)));
    }

    // CONTRACT.md §2: a token is at most 4096 bytes.
    // A 3025-byte URL makes a 3033-byte bag object, a 4044-character bag and a 4095-byte token.
    // One more byte makes a 4046-character bag and a 4097-byte token, since no base64url text has 4045 characters.
    [Fact]
    public void CreateAcceptsTheLongestUrlThatFits()
    {
        EnrollmentToken token = EnrollmentToken.Create(UrlOfLength(3025), new ReplayingGenerator(SecretBytes));

        Assert.Equal(4095, token.Value.Length);
    }

    [Fact]
    public void CreateRejectsAUrlThatMakesTheTokenTooLong()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EnrollmentToken.Create(UrlOfLength(3026), new ReplayingGenerator(SecretBytes)));

        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    // INTENT.agent-identity.md, security invariant 9: tokens never appear in logs, not even partially,
    // and a log statement may format the token object.
    [Fact]
    public void ToStringRevealsNoPartOfTheToken()
    {
        EnrollmentToken token = EnrollmentToken.Create("https://host/dvls", new ReplayingGenerator(SecretBytes));
        string[] segments = token.Value.Split('.');

        EnrollmentTokenAssert.RevealsNoPart(token.ToString(), segments[1], segments[2]);
    }

    // INTENT.agent-identity.md, security invariant 9: a host may log the exception of a failed creation.
    public static TheoryData<string> RejectedUrlRows => new([.. UnacceptableUrls, UrlOfLength(3026)]);

    [Theory]
    [MemberData(nameof(RejectedUrlRows))]
    public void CreateFailureRevealsNoPartOfTheSecret(string productBaseUrl)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => EnrollmentToken.Create(productBaseUrl, new ReplayingGenerator(SecretBytes)));

        EnrollmentTokenAssert.RevealsNoPart(exception.Message, SecretText);
    }

    [Fact]
    public void CreateRejectsANullUrl()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentToken.Create(null!, new ReplayingGenerator(SecretBytes)));

        Assert.Equal("productBaseUrl", exception.ParamName);
    }

    [Fact]
    public void CreateRejectsANullGenerator()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => EnrollmentToken.Create("https://host/dvls", null!));

        Assert.Equal("randomNumberGenerator", exception.ParamName);
    }

    private static string UrlOfLength(int length)
    {
        const string prefix = "https://host/";

        return prefix + new string('a', length - prefix.Length);
    }

    // Reads the members of the bag, after checking that the bag is the canonical base64url encoding of its bytes.
    private static (string Name, string? Value)[] BagMembers(EnrollmentToken token)
    {
        string bag = token.Value.Split('.')[1];
        Assert.True(Base64Url.IsValid(bag));
        byte[] json = Base64Url.DecodeFromChars(bag);
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
