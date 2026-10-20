using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Devolutions.AgentIdentity.Tests;

public class StrictBase64Tests
{
    // RFC 4648 Table 1 and Table 2.
    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // CONTRACT.md: base64 is RFC 4648 §4 with padding, and base64url is RFC 4648 §5 without padding.
    private static readonly Dictionary<string, Codec> Codecs = new()
    {
        ["base64"] = new(StrictBase64.TryDecodeBase64, Base64Alphabet, "==", "=", base64 => base64),
        ["base64url"] = new(StrictBase64.TryDecodeBase64Url, Base64UrlAlphabet, "", "", ToBase64Url),
    };

    private delegate bool Decoder(ReadOnlySpan<char> text, [NotNullWhen(true)] out byte[]? bytes, int? exactLength);

    // RFC 4648 §10 test vectors, which base64url writes without padding, as RFC 4648 §3.2 lets an encoding do.
    // In the last row of each encoding, the sextets 62, 63 and 60 carry the bytes FB FF and two zero pad bits;
    // RFC 4648 Table 1 writes them "+/8" and Table 2 writes them "-_8".
    public static TheoryData<string, string, byte[]> CanonicalForms => new()
    {
        { "base64", "", Ascii("") },
        { "base64", "Zg==", Ascii("f") },
        { "base64", "Zm8=", Ascii("fo") },
        { "base64", "Zm9v", Ascii("foo") },
        { "base64", "Zm9vYg==", Ascii("foob") },
        { "base64", "Zm9vYmE=", Ascii("fooba") },
        { "base64", "Zm9vYmFy", Ascii("foobar") },
        { "base64", "+/8=", [0xFB, 0xFF] },
        { "base64url", "", Ascii("") },
        { "base64url", "Zg", Ascii("f") },
        { "base64url", "Zm8", Ascii("fo") },
        { "base64url", "Zm9v", Ascii("foo") },
        { "base64url", "Zm9vYg", Ascii("foob") },
        { "base64url", "Zm9vYmE", Ascii("fooba") },
        { "base64url", "Zm9vYmFy", Ascii("foobar") },
        { "base64url", "-_8", [0xFB, 0xFF] },
    };

    // The base64url rows of CanonicalForms, which the encoder writes from their bytes.
    public static TheoryData<string, byte[]> Base64UrlForms => new()
    {
        { "", Ascii("") },
        { "Zg", Ascii("f") },
        { "Zm8", Ascii("fo") },
        { "Zm9v", Ascii("foo") },
        { "Zm9vYg", Ascii("foob") },
        { "Zm9vYmE", Ascii("fooba") },
        { "Zm9vYmFy", Ascii("foobar") },
        { "-_8", [0xFB, 0xFF] },
    };

    [Theory]
    [MemberData(nameof(CanonicalForms))]
    public void DecodesTheCanonicalForm(string encoding, string encoded, byte[] expected)
    {
        Assert.True(Codecs[encoding].TryDecode(encoded, out byte[]? bytes, null));
        Assert.Equal(expected, bytes);
    }

    // Each row is a form that RFC 4648 §4, or §5 without padding, does not produce for any byte string,
    // so accepting it would give one value two encodings.
    [Theory]
    [InlineData("base64", "missing padding", "Zg")]
    [InlineData("base64", "missing one padding character", "Zm9vYg=")]
    [InlineData("base64", "padding after a complete quantum", "Zm9v====")]
    [InlineData("base64", "padding inside the text", "Zg==Zm9v")]
    [InlineData("base64", "padding only", "====")]
    [InlineData("base64", "line break between quanta", "Zm9v\r\nYmFy")]
    [InlineData("base64", "trailing space", "Zm9vYmFy ")]
    [InlineData("base64", "non-zero pad bits after one byte", "Zh==")]
    [InlineData("base64", "non-zero pad bits after two bytes", "Zm9=")]
    [InlineData("base64", "base64url alphabet", "-_8=")]
    [InlineData("base64", "character outside ASCII whose low byte is 'v'", "Zm9\u0176")]
    [InlineData("base64url", "padding after one byte", "Zg==")]
    [InlineData("base64url", "padding after two bytes", "Zm8=")]
    [InlineData("base64url", "impossible length", "Zm9vY")]
    [InlineData("base64url", "line break between quanta", "Zm9v\r\nYmFy")]
    [InlineData("base64url", "trailing space", "Zm9vYmFy ")]
    [InlineData("base64url", "non-zero pad bits after one byte", "Zh")]
    [InlineData("base64url", "non-zero pad bits after two bytes", "Zm9")]
    [InlineData("base64url", "base64 alphabet", "+/8")]
    [InlineData("base64url", "character outside ASCII whose low byte is 'v'", "Zm9\u0176")]
    public void RejectsANonCanonicalForm(string encoding, string form, string encoded)
    {
        Assert.False(Codecs[encoding].TryDecode(encoded, out _, null), form);
    }

    // RFC 4648 §10 vectors with the number of bytes they encode; padding characters encode none.
    [Theory]
    [InlineData("base64", "", 0)]
    [InlineData("base64", "Zg==", 1)]
    [InlineData("base64", "Zm8=", 2)]
    [InlineData("base64", "Zm9v", 3)]
    [InlineData("base64url", "", 0)]
    [InlineData("base64url", "Zg", 1)]
    [InlineData("base64url", "Zm8", 2)]
    [InlineData("base64url", "Zm9v", 3)]
    public void AcceptsTheExactDecodedLength(string encoding, string encoded, int length)
    {
        Assert.True(Codecs[encoding].TryDecode(encoded, out byte[]? bytes, length));
        Assert.Equal(length, bytes.Length);
    }

    [Theory]
    [InlineData("base64", "", 1)]
    [InlineData("base64", "Zg==", 0)]
    [InlineData("base64", "Zg==", 3)]
    [InlineData("base64", "Zm8=", 3)]
    [InlineData("base64", "Zm9v", 2)]
    [InlineData("base64", "Zm9v", 4)]
    [InlineData("base64url", "", 1)]
    [InlineData("base64url", "Zg", 0)]
    [InlineData("base64url", "Zg", 2)]
    [InlineData("base64url", "Zm8", 3)]
    [InlineData("base64url", "Zm9v", 2)]
    [InlineData("base64url", "Zm9v", 4)]
    public void RejectsAnotherDecodedLength(string encoding, string encoded, int length)
    {
        Assert.False(Codecs[encoding].TryDecode(encoded, out _, length));
    }

    [Theory]
    [MemberData(nameof(Base64UrlForms))]
    public void Base64UrlEncodesWithoutPadding(string expected, byte[] value)
    {
        Assert.Equal(expected, StrictBase64.EncodeBase64Url(value));
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
    [Theory]
    [InlineData("base64")]
    [InlineData("base64url")]
    public void AcceptsOneEncodingOfEachOneOrTwoByteValue(string encoding)
    {
        Codec codec = Codecs[encoding];
        IEnumerable<string> finalQuanta = Strings(codec.Alphabet, 2).Select(s => s + codec.OneBytePadding)
            .Concat(Strings(codec.Alphabet, 3).Select(s => s + codec.TwoBytePadding));
        IEnumerable<string> canonical = OneOrTwoByteValues()
            .Select(value => codec.FromBase64(Convert.ToBase64String(value)));

        IEnumerable<string> accepted = finalQuanta.Where(s => codec.TryDecode(s, out _, null));

        Assert.Equal(canonical.Order(StringComparer.Ordinal), accepted.Order(StringComparer.Ordinal));
    }

    private static byte[] Ascii(string text)
    {
        return Encoding.ASCII.GetBytes(text);
    }

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

    /// <summary>
    /// An encoding with its decoder under test, its alphabet, and the padding of a final quantum.
    /// </summary>
    /// <param name="FromBase64">Converts canonical base64 to the canonical form of this encoding.</param>
    private sealed record Codec(
        Decoder TryDecode,
        string Alphabet,
        string OneBytePadding,
        string TwoBytePadding,
        Func<string, string> FromBase64);
}