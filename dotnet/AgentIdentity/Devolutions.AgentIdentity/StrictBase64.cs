using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// Decoders that accept only the canonical RFC 4648 form, so that each byte string has exactly one accepted encoding.
/// </summary>
/// <remarks>
/// The BCL decoders skip white space and ignore the pad bits of the final quantum,
/// so they accept several encodings of one value.
/// </remarks>
internal static class StrictBase64
{
    /// <summary>
    /// Decodes <c>base64</c> (RFC 4648 §4) with padding.
    /// </summary>
    /// <remarks>
    /// Rejects white space, characters outside the alphabet, missing or extra padding, and non-zero pad bits.
    /// </remarks>
    /// <param name="text">The encoded text.</param>
    /// <param name="bytes">The decoded bytes, when the text is canonical.</param>
    /// <param name="exactLength">The number of bytes the text must decode to, if any.</param>
    public static bool TryDecodeBase64(
        ReadOnlySpan<char> text,
        [NotNullWhen(true)] out byte[]? bytes,
        int? exactLength = null)
    {
        bytes = null;

        if (text.Length % 4 != 0)
        {
            return false;
        }

        int padding = text.EndsWith("==") ? 2 : text.EndsWith("=") ? 1 : 0;

        return TryDecodeUnpadded(text[..^padding], urlSafe: false, exactLength, out bytes);
    }

    /// <summary>
    /// Decodes <c>base64url</c> (RFC 4648 §5) without padding.
    /// </summary>
    /// <remarks>
    /// Rejects white space, characters outside the alphabet, padding, and non-zero pad bits.
    /// </remarks>
    /// <param name="text">The encoded text.</param>
    /// <param name="bytes">The decoded bytes, when the text is canonical.</param>
    /// <param name="exactLength">The number of bytes the text must decode to, if any.</param>
    public static bool TryDecodeBase64Url(
        ReadOnlySpan<char> text,
        [NotNullWhen(true)] out byte[]? bytes,
        int? exactLength = null)
    {
        return TryDecodeUnpadded(text, urlSafe: true, exactLength, out bytes);
    }

    /// <summary>
    /// Encodes bytes as <c>base64url</c> (RFC 4648 §5) without padding.
    /// </summary>
    public static string EncodeBase64Url(ReadOnlySpan<byte> bytes)
    {
        return Base64Url.EncodeToString(bytes);
    }

    private static bool TryDecodeUnpadded(
        ReadOnlySpan<char> text,
        bool urlSafe,
        int? exactLength,
        [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;

        // A final quantum of one character would hold fewer than 8 bits.
        int partial = text.Length % 4;
        if (partial == 1)
        {
            return false;
        }

        int length = (text.Length / 4 * 3) + (partial == 0 ? 0 : partial - 1);
        if (exactLength is { } expected && length != expected)
        {
            return false;
        }

        byte[] decoded = new byte[length];
        int written = 0;
        int accumulator = 0;
        int bitCount = 0;

        foreach (char c in text)
        {
            int sextet = DecodeSextet(c, urlSafe);
            if (sextet < 0)
            {
                return false;
            }

            accumulator = (accumulator << 6) | sextet;
            bitCount += 6;

            if (bitCount >= 8)
            {
                bitCount -= 8;
                decoded[written++] = (byte)(accumulator >> bitCount);
                accumulator &= (1 << bitCount) - 1;
            }
        }

        // The bits left over are the pad bits of the final quantum, which the canonical encoding sets to zero.
        if (accumulator != 0)
        {
            return false;
        }

        bytes = decoded;
        return true;
    }

    private static int DecodeSextet(char c, bool urlSafe)
    {
        return c switch
        {
            >= 'A' and <= 'Z' => c - 'A',
            >= 'a' and <= 'z' => c - 'a' + 26,
            >= '0' and <= '9' => c - '0' + 52,
            '+' when !urlSafe => 62,
            '/' when !urlSafe => 63,
            '-' when urlSafe => 62,
            '_' when urlSafe => 63,
            _ => -1,
        };
    }
}
