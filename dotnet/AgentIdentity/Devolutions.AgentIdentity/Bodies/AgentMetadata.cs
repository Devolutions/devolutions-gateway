using System.Buffers;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Devolutions.AgentIdentity;

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
    /// Each value is Unicode text of at most 1024 UTF-8 bytes without C0, DEL or C1 control characters,
    /// and the UTF-8 lengths of all keys and values add up to at most 16 KiB.
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

            if (!IsValidKey(key))
            {
                return MetadataValidationResult.Failure(
                    $"Metadata key {validated.Count + 1} does not match ^[a-z][a-z0-9_]{{0,63}}$.");
            }

            if (validated.ContainsKey(key))
            {
                return MetadataValidationResult.Failure($"The metadata repeats the key '{key}'.");
            }

            if (CheckValue(value, out int valueBytes) is { } problem)
            {
                return MetadataValidationResult.Failure($"The value of metadata key '{key}' {problem}.");
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
                return $"holds the control character U+{rune.Value:X4}";
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
}
