using System.Buffers;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Metadata that an agent reported, such as its host name and OS version, checked against the limits of the protocol.
/// </summary>
/// <remarks>
/// Metadata is informational, for display and friendly-name evaluation, and never authorizes anything.
/// Only <see cref="Validate"/> and the request body parsers create instances,
/// so an instance always holds valid metadata.
/// Keys compare ordinally, and enumeration follows the order in which the agent sent the entries.
/// </remarks>
public sealed class AgentMetadata : IReadOnlyDictionary<string, string>
{
    private const int MaxKeys = 32;
    private const int MaxKeyLength = 64;
    private const int MaxValueBytes = 1024;
    private const int MaxTotalBytes = 16 * 1024;

    private readonly OrderedDictionary<string, string> _entries;

    private AgentMetadata(OrderedDictionary<string, string> entries)
    {
        _entries = entries;
    }

    /// <inheritdoc/>
    public int Count => _entries.Count;

    /// <inheritdoc/>
    public IEnumerable<string> Keys => _entries.Keys;

    /// <inheritdoc/>
    public IEnumerable<string> Values => _entries.Values;

    /// <inheritdoc/>
    public string this[string key] => _entries[key];

    /// <summary>
    /// Validates metadata received from an agent, such as the metadata of a <c>Hello</c> message.
    /// </summary>
    /// <remarks>
    /// Valid metadata has at most 32 keys, each matching <c>^[a-z][a-z0-9_]{0,63}$</c> and appearing once.
    /// Each value is Unicode text of at most 1024 UTF-8 bytes without C0, DEL or C1 control characters
    /// or the invisible format characters U+00AD, U+034F, U+061C, U+115F to U+1160, U+17B4 to U+17B5,
    /// U+180B to U+180F, U+200B to U+200F, U+202A to U+202E, U+2060 to U+206F, U+3164, U+FE00 to U+FE0F,
    /// U+FEFF, U+FFA0, U+FFF0 to U+FFFB, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A and U+E0000 to U+E0FFF.
    /// The UTF-8 lengths of all keys and values add up to at most 16 KiB.
    /// </remarks>
    /// <param name="entries">The metadata entries, in the order received.</param>
    /// <exception cref="ArgumentException">An entry has a null key or value.</exception>
    public static MetadataValidationResult Validate(IEnumerable<KeyValuePair<string, string>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        OrderedDictionary<string, string> validated = new(StringComparer.Ordinal);
        int totalBytes = 0;

        foreach ((string key, string value) in entries)
        {
            if (key is null || value is null)
            {
                throw new ArgumentException("A metadata entry has a null key or value.", nameof(entries));
            }

            if (validated.Count == MaxKeys)
            {
                return MetadataValidationResult.Failure($"The metadata has more than {MaxKeys} keys.");
            }

            // A detail names an entry by its position, because the key comes from the request.
            int position = validated.Count + 1;

            if (!IsValidKey(key))
            {
                return MetadataValidationResult.Failure(
                    $"Metadata key {position} does not match ^[a-z][a-z0-9_]{{0,63}}$.");
            }

            if (validated.ContainsKey(key))
            {
                return MetadataValidationResult.Failure($"Metadata key {position} repeats an earlier key.");
            }

            if (CheckValue(value, out int valueBytes) is { } problem)
            {
                return MetadataValidationResult.Failure($"The value of metadata key {position} {problem}.");
            }

            // Keys are ASCII, so each character is one UTF-8 byte.
            totalBytes += key.Length + valueBytes;
            if (totalBytes > MaxTotalBytes)
            {
                return MetadataValidationResult.Failure(
                    $"The metadata keys and values have more than {MaxTotalBytes} UTF-8 bytes.");
            }

            validated.Add(key, value);
        }

        return MetadataValidationResult.Success(new AgentMetadata(validated));
    }

    /// <inheritdoc/>
    public bool ContainsKey(string key)
    {
        return _entries.ContainsKey(key);
    }

    /// <inheritdoc/>
    public bool TryGetValue(string key, [MaybeNullWhen(false)] out string value)
    {
        return _entries.TryGetValue(key, out value);
    }

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
    {
        return _entries.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    // Checks the key against ^[a-z][a-z0-9_]{0,63}$ character by character:
    // a .NET regular expression ending in $ would also accept a final line feed.
    private static bool IsValidKey(string key)
    {
        if (key.Length is 0 or > MaxKeyLength || key[0] is not (>= 'a' and <= 'z'))
        {
            return false;
        }

        foreach (char c in key)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '_'))
            {
                return false;
            }
        }

        return true;
    }

    // Returns why the value is invalid, or null and its UTF-8 length.
    private static string? CheckValue(string value, out int utf8Length)
    {
        utf8Length = 0;
        ReadOnlySpan<char> remaining = value;

        while (!remaining.IsEmpty)
        {
            // An unpaired surrogate encodes no Unicode scalar value, so the string has no UTF-8 form.
            if (Rune.DecodeFromUtf16(remaining, out Rune rune, out int consumed) != OperationStatus.Done)
            {
                return "is not valid Unicode";
            }

            if (rune.Value is <= 0x1F or (>= 0x7F and <= 0x9F))
            {
                return "holds a control character";
            }

            if (IsInvisibleFormatCharacter(rune.Value))
            {
                return "holds an invisible format character";
            }

            utf8Length += rune.Utf8SequenceLength;
            if (utf8Length > MaxValueBytes)
            {
                return $"is longer than {MaxValueBytes} UTF-8 bytes";
            }

            remaining = remaining[consumed..];
        }

        return null;
    }

    // The invisible format characters of the protocol, which could reorder or hide text where an administrator reads it.
    // The protocol fixes them as code points rather than through a Unicode property such as Default_Ignorable_Code_Point,
    // so that the agent and every authority agree whatever Unicode version their runtimes ship.
    private static bool IsInvisibleFormatCharacter(int codePoint)
    {
        return codePoint is 0x00AD or 0x034F or 0x061C
            or (>= 0x115F and <= 0x1160)
            or (>= 0x17B4 and <= 0x17B5)
            or (>= 0x180B and <= 0x180F)
            or (>= 0x200B and <= 0x200F)
            or (>= 0x202A and <= 0x202E)
            or (>= 0x2060 and <= 0x206F)
            or 0x3164
            or (>= 0xFE00 and <= 0xFE0F)
            or 0xFEFF
            or 0xFFA0
            or (>= 0xFFF0 and <= 0xFFFB)
            or (>= 0x1BCA0 and <= 0x1BCA3)
            or (>= 0x1D173 and <= 0x1D17A)
            or (>= 0xE0000 and <= 0xE0FFF);
    }
}
