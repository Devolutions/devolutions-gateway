using System.Text;

namespace Devolutions.AgentIdentity.Tests;

public class StrictBase64Tests
{
    // RFC 4648 §10 test vectors.
    [Theory]
    [InlineData("", "")]
    [InlineData("Zg==", "f")]
    [InlineData("Zm8=", "fo")]
    [InlineData("Zm9v", "foo")]
    [InlineData("Zm9vYg==", "foob")]
    [InlineData("Zm9vYmE=", "fooba")]
    [InlineData("Zm9vYmFy", "foobar")]
    public void Base64DecodesRfc4648Vector(string encoded, string expected)
    {
        Assert.True(StrictBase64.TryDecodeBase64(encoded, out byte[]? bytes));
        Assert.Equal(Encoding.ASCII.GetBytes(expected), bytes);
    }

    // Each row is a form that RFC 4648 §4 does not produce for any byte string,
    // so accepting it would give one value two encodings.
    [Theory]
    [InlineData("missing padding", "Zg")]
    [InlineData("missing one padding character", "Zm9vYg=")]
    [InlineData("padding after a complete quantum", "Zm9v====")]
    [InlineData("padding inside the text", "Zg==Zm9v")]
    [InlineData("padding only", "====")]
    [InlineData("line break between quanta", "Zm9v\r\nYmFy")]
    [InlineData("trailing space", "Zm9vYmFy ")]
    [InlineData("non-zero pad bits after one byte", "Zh==")]
    [InlineData("non-zero pad bits after two bytes", "Zm9=")]
    [InlineData("base64url alphabet", "-_8=")]
    [InlineData("character outside ASCII whose low byte is 'v'", "Zm9\u0176")]
    public void Base64RejectsNonCanonicalForm(string form, string encoded)
    {
        Assert.False(StrictBase64.TryDecodeBase64(encoded, out _), form);
    }

    // RFC 4648 §10 test vectors without padding, which RFC 4648 §3.2 lets an encoding omit.
    [Theory]
    [InlineData("", "")]
    [InlineData("Zg", "f")]
    [InlineData("Zm8", "fo")]
    [InlineData("Zm9v", "foo")]
    [InlineData("Zm9vYg", "foob")]
    [InlineData("Zm9vYmE", "fooba")]
    [InlineData("Zm9vYmFy", "foobar")]
    public void Base64UrlDecodesRfc4648Vector(string encoded, string expected)
    {
        Assert.True(StrictBase64.TryDecodeBase64Url(encoded, out byte[]? bytes));
        Assert.Equal(Encoding.ASCII.GetBytes(expected), bytes);
    }

    // The sextets 62, 63 and 60 carry the bytes FB FF and two zero pad bits;
    // RFC 4648 Table 1 writes them "+/8" and Table 2 writes them "-_8".
    [Fact]
    public void Base64DecodesTheLastTwoAlphabetCharacters()
    {
        Assert.True(StrictBase64.TryDecodeBase64("+/8=", out byte[]? bytes));
        Assert.Equal([0xFB, 0xFF], bytes);
    }

    [Fact]
    public void Base64UrlDecodesTheLastTwoAlphabetCharacters()
    {
        Assert.True(StrictBase64.TryDecodeBase64Url("-_8", out byte[]? bytes));
        Assert.Equal([0xFB, 0xFF], bytes);
    }

    // Each row is a form that RFC 4648 §5 without padding does not produce for any byte string.
    [Theory]
    [InlineData("padding after one byte", "Zg==")]
    [InlineData("padding after two bytes", "Zm8=")]
    [InlineData("impossible length", "Zm9vY")]
    [InlineData("line break between quanta", "Zm9v\r\nYmFy")]
    [InlineData("trailing space", "Zm9vYmFy ")]
    [InlineData("non-zero pad bits after one byte", "Zh")]
    [InlineData("non-zero pad bits after two bytes", "Zm9")]
    [InlineData("base64 alphabet", "+/8")]
    [InlineData("character outside ASCII whose low byte is 'v'", "Zm9\u0176")]
    public void Base64UrlRejectsNonCanonicalForm(string form, string encoded)
    {
        Assert.False(StrictBase64.TryDecodeBase64Url(encoded, out _), form);
    }

    // RFC 4648 §10 vectors with the number of bytes they encode; padding characters encode none.
    [Theory]
    [InlineData("", 0)]
    [InlineData("Zg==", 1)]
    [InlineData("Zm8=", 2)]
    [InlineData("Zm9v", 3)]
    public void Base64AcceptsTheExactDecodedLength(string encoded, int length)
    {
        Assert.True(StrictBase64.TryDecodeBase64(encoded, out byte[]? bytes, exactLength: length));
        Assert.Equal(length, bytes.Length);
    }

    [Theory]
    [InlineData("", 1)]
    [InlineData("Zg==", 0)]
    [InlineData("Zg==", 3)]
    [InlineData("Zm8=", 3)]
    [InlineData("Zm9v", 2)]
    [InlineData("Zm9v", 4)]
    public void Base64RejectsAnotherDecodedLength(string encoded, int length)
    {
        Assert.False(StrictBase64.TryDecodeBase64(encoded, out _, exactLength: length));
    }

    [Theory]
    [InlineData("", 0)]
    [InlineData("Zg", 1)]
    [InlineData("Zm8", 2)]
    [InlineData("Zm9v", 3)]
    public void Base64UrlAcceptsTheExactDecodedLength(string encoded, int length)
    {
        Assert.True(StrictBase64.TryDecodeBase64Url(encoded, out byte[]? bytes, exactLength: length));
        Assert.Equal(length, bytes.Length);
    }

    [Theory]
    [InlineData("", 1)]
    [InlineData("Zg", 0)]
    [InlineData("Zg", 2)]
    [InlineData("Zm8", 3)]
    [InlineData("Zm9v", 2)]
    [InlineData("Zm9v", 4)]
    public void Base64UrlRejectsAnotherDecodedLength(string encoded, int length)
    {
        Assert.False(StrictBase64.TryDecodeBase64Url(encoded, out _, exactLength: length));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("f", "Zg")]
    [InlineData("fo", "Zm8")]
    [InlineData("foo", "Zm9v")]
    [InlineData("foob", "Zm9vYg")]
    [InlineData("fooba", "Zm9vYmE")]
    [InlineData("foobar", "Zm9vYmFy")]
    public void Base64UrlEncodesRfc4648VectorWithoutPadding(string decoded, string expected)
    {
        Assert.Equal(expected, StrictBase64.EncodeBase64Url(Encoding.ASCII.GetBytes(decoded)));
    }

    [Fact]
    public void Base64UrlEncodesTheLastTwoAlphabetCharacters()
    {
        Assert.Equal("-_8", StrictBase64.EncodeBase64Url([0xFB, 0xFF]));
    }

    // The BCL encoder writes canonical base64,
    // and RFC 4648 §5 derives base64url from it by swapping the last two characters and dropping the padding.
    // Random values of every length up to 96 bytes end in each final-quantum shape many times.
    [Fact]
    public void DecodesAndEncodesEveryLengthLikeTheBcl()
    {
        Random random = new(4648);

        for (int length = 0; length <= 96; length++)
        {
            byte[] value = new byte[length];
            random.NextBytes(value);
            string base64 = Convert.ToBase64String(value);
            string base64Url = ToBase64Url(base64);

            Assert.True(StrictBase64.TryDecodeBase64(base64, out byte[]? fromBase64), base64);
            Assert.Equal(value, fromBase64);
            Assert.True(StrictBase64.TryDecodeBase64Url(base64Url, out byte[]? fromBase64Url), base64Url);
            Assert.Equal(value, fromBase64Url);
            Assert.Equal(base64Url, StrictBase64.EncodeBase64Url(value));
        }
    }

    // Only the final quantum has pad bits,
    // so trying every final quantum of one or two bytes checks that each value has exactly one accepted encoding.
    [Fact]
    public void Base64AcceptsOneEncodingOfEachOneOrTwoByteValue()
    {
        IEnumerable<string> finalQuanta = Strings(Base64Alphabet, 2).Select(s => s + "==")
            .Concat(Strings(Base64Alphabet, 3).Select(s => s + "="));
        IEnumerable<string> canonical = OneOrTwoByteValues().Select(Convert.ToBase64String);

        IEnumerable<string> accepted = finalQuanta.Where(s => StrictBase64.TryDecodeBase64(s, out _));

        Assert.Equal(canonical.Order(StringComparer.Ordinal), accepted.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Base64UrlAcceptsOneEncodingOfEachOneOrTwoByteValue()
    {
        IEnumerable<string> finalQuanta = Strings(Base64UrlAlphabet, 2).Concat(Strings(Base64UrlAlphabet, 3));
        IEnumerable<string> canonical = OneOrTwoByteValues().Select(value => ToBase64Url(Convert.ToBase64String(value)));

        IEnumerable<string> accepted = finalQuanta.Where(s => StrictBase64.TryDecodeBase64Url(s, out _));

        Assert.Equal(canonical.Order(StringComparer.Ordinal), accepted.Order(StringComparer.Ordinal));
    }

    // RFC 4648 Table 1 and Table 2.
    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    private static string ToBase64Url(string base64)
    {
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static IEnumerable<string> Strings(string alphabet, int length)
    {
        return length == 0
            ? [string.Empty]
            : Strings(alphabet, length - 1).SelectMany(prefix => alphabet.Select(c => prefix + c));
    }

    private static IEnumerable<byte[]> OneOrTwoByteValues()
    {
        return Enumerable.Range(0, 1 << 8).Select(v => new[] { (byte)v })
            .Concat(Enumerable.Range(0, 1 << 16).Select(v => new[] { (byte)(v >> 8), (byte)v }));
    }
}
