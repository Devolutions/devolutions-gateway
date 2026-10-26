using System.Collections;

namespace Devolutions.Agent.Identity.Authority.Tests;

public class AgentMetadataTests
{
    // Text that the entry where the metadata fails holds in its key and in its value.
    private const string LeakedKey = "leaked_key";
    private const string LeakedValue = "leaked value";

    // Metadata that breaks each rule of CONTRACT.agent-identity.md §1 and §3, by name,
    // at an entry whose key holds LeakedKey and whose value holds LeakedValue.
    private static readonly Dictionary<string, KeyValuePair<string, string>[]> Failures = new()
    {
        ["33 keys"] = [.. Enumerable.Range(0, 33).Select(i => Entry($"{LeakedKey}_{i}", LeakedValue))],
        ["key outside the pattern"] = [Entry($"{LeakedKey}\n", LeakedValue)],
        ["repeated key"] = [Entry(LeakedKey, "first"), Entry(LeakedKey, LeakedValue)],
        ["value with a control character"] = [Entry(LeakedKey, $"{LeakedValue}\u0007")],
        ["value that is not Unicode"] = [Entry(LeakedKey, $"{LeakedValue}\uD800")],
        ["value of 1025 UTF-8 bytes"] = [Entry(LeakedKey, LeakedValue + new string('a', 1025 - LeakedValue.Length))],

        // 17 entries of 13 + 1000 bytes: the first 16 hold 16208 bytes, and all 17 hold 17221, past 16 KiB.
        ["object over 16 KiB"] =
        [
            .. Enumerable.Range(0, 17)
                .Select(i => Entry($"{LeakedKey}_{i:D2}", LeakedValue + new string('a', 1000 - LeakedValue.Length))),
        ],
    };

    public static TheoryData<string> FailureNames => new(Failures.Keys);

    // Metadata may be an empty object.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void AcceptsNoEntries()
    {
        AgentMetadata metadata = AssertValid(AgentMetadata.Validate([]));

        Assert.Empty(metadata);
    }

    // Metadata is a JSON object of string to string, and keeps each entry received.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void KeepsEveryEntryReceived()
    {
        KeyValuePair<string, string>[] entries =
        [
            new("os_name", "Windows"),
            new("hostname", "host"),
            new("agent_version", "2026.3.0"),
        ];

        AgentMetadata metadata = AssertValid(AgentMetadata.Validate(entries));

        Assert.Equal(
            entries.OrderBy(entry => entry.Key, StringComparer.Ordinal),
            metadata.OrderBy(entry => entry.Key, StringComparer.Ordinal));
        Assert.Equal("host", metadata["hostname"]);
    }

    // A host that enumerates the metadata through the non-generic IEnumerable sees the same entries in the same order.
    // Enumerable.Cast would take the generic enumerator, so the loop calls the non-generic one.
    // oracle: mutant the non-generic GetEnumerator returns no enumerator instead of the entries
    [Fact]
    public void NonGenericEnumerationKeepsEveryEntryInTheOrderReceived()
    {
        KeyValuePair<string, string>[] entries = [new("os_name", "Windows"), new("hostname", "host")];
        AgentMetadata metadata = AssertValid(AgentMetadata.Validate(entries));

        List<KeyValuePair<string, string>> enumerated = [];
        foreach (KeyValuePair<string, string> entry in (IEnumerable)metadata)
        {
            enumerated.Add(entry);
        }

        Assert.Equal(entries, enumerated);
    }

    // IReadOnlyDictionary<TKey, TValue>.ContainsKey is true for a key received and false for any other.
    // oracle: spec .NET API reference §IReadOnlyDictionary<TKey,TValue>.ContainsKey
    [Fact]
    public void ContainsOnlyTheKeysReceived()
    {
        AgentMetadata metadata = AssertValid(AgentMetadata.Validate([new("hostname", "host")]));

        Assert.True(metadata.ContainsKey("hostname"));
        Assert.False(metadata.ContainsKey("absent"));
    }

    // At most 32 keys.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void Accepts32Keys()
    {
        AgentMetadata metadata = AssertValid(AgentMetadata.Validate(NumberedEntries(32)));

        Assert.Equal(32, metadata.Count);
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void Rejects33Keys()
    {
        AssertInvalid(AgentMetadata.Validate(NumberedEntries(33)));
    }

    // A key matches ^[a-z][a-z0-9_]{0,63}$.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [InlineData("a")]
    [InlineData("hostname")]
    [InlineData("os_version")]
    [InlineData("z9_")]
    [InlineData("abcdefghijklmnopqrstuvwxyz0123456789_")]
    public void AcceptsKeyMatchingThePattern(string key)
    {
        AssertValid(AgentMetadata.Validate([new(key, "value")]));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void AcceptsKeyOf64Characters()
    {
        AssertValid(AgentMetadata.Validate([new("k" + new string('0', 63), "value")]));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void RejectsKeyOf65Characters()
    {
        AssertInvalid(AgentMetadata.Validate([new("k" + new string('0', 64), "value")]));
    }

    // A case-insensitive match would take the Kelvin sign for 'k',
    // and a .NET regular expression ending in $ also matches before a final line feed.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [InlineData("empty", "")]
    [InlineData("uppercase first letter", "Hostname")]
    [InlineData("uppercase letter", "hostName")]
    [InlineData("leading digit", "1hostname")]
    [InlineData("leading underscore", "_hostname")]
    [InlineData("hyphen", "os-name")]
    [InlineData("space", "os name")]
    [InlineData("trailing line feed", "hostname\n")]
    [InlineData("non-ASCII letter", "h\u00F4stname")]
    [InlineData("Kelvin sign", "\u212Aey")]
    [InlineData("fullwidth letter", "\uFF48ostname")]
    public void RejectsKeyNotMatchingThePattern(string form, string key)
    {
        AssertInvalid(AgentMetadata.Validate([new(key, "value")]), form);
    }

    // A value has at most 1024 UTF-8 bytes.
    // Characters of two, three and four bytes count by their bytes, not as one character or UTF-16 code unit.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [InlineData("a", 1024, "")]
    [InlineData("\u00E9", 512, "")]
    [InlineData("\u20AC", 341, "a")]
    [InlineData("\U0001F600", 256, "")]
    public void AcceptsValueOf1024Utf8Bytes(string unit, int count, string suffix)
    {
        AssertValid(AgentMetadata.Validate([new("hostname", Repeat(unit, count) + suffix)]));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [InlineData("a", 1025, "")]
    [InlineData("\u00E9", 512, "a")]
    [InlineData("\u20AC", 341, "aa")]
    [InlineData("\U0001F600", 256, "a")]
    public void RejectsValueOf1025Utf8Bytes(string unit, int count, string suffix)
    {
        AssertInvalid(AgentMetadata.Validate([new("hostname", Repeat(unit, count) + suffix)]));
    }

    // CONTRACT.agent-identity.md §3 gives a value no minimum length.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void AcceptsEmptyValue()
    {
        AssertValid(AgentMetadata.Validate([new("domain", "")]));
    }

    // No C0 (U+0000 to U+001F), DEL (U+007F) or C1 (U+0080 to U+009F) control characters.
    public static TheoryData<int> ControlCharacters =>
        new(Enumerable.Range(0x00, 0x20).Append(0x7F).Concat(Enumerable.Range(0x80, 0x20)));

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [MemberData(nameof(ControlCharacters))]
    public void RejectsValueWithControlCharacter(int codePoint)
    {
        AssertInvalid(AgentMetadata.Validate([new("hostname", $"host{(char)codePoint}name")]));
    }

    // The neighbors of the control ranges, including U+00A0, the first character after C1.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [InlineData(0x20)]
    [InlineData(0x7E)]
    [InlineData(0xA0)]
    public void AcceptsValueWithCharacterNextToAControlRange(int codePoint)
    {
        AssertValid(AgentMetadata.Validate([new("hostname", $"host{(char)codePoint}name")]));
    }

    // CONTRACT.agent-identity.md §3 measures a value in UTF-8 bytes.
    // A string holding an unpaired surrogate is not Unicode text, so it has no UTF-8 encoding to measure or store.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    // oracle: spec RFC 3629 §3
    [Theory]
    [InlineData("lone high surrogate", 0x61, 0xD800, 0x62)]
    [InlineData("lone low surrogate", 0x61, 0xDC00, 0x62)]
    [InlineData("high surrogate at the end", 0x61, 0xD800)]
    [InlineData("pair in reverse order", 0xDC00, 0xD800)]
    public void RejectsValueWithUnpairedSurrogate(string form, params int[] codeUnits)
    {
        string value = new(codeUnits.Select(unit => (char)unit).ToArray());

        AssertInvalid(AgentMetadata.Validate([new("hostname", value)]), form);
    }

    // The whole object has at most 16 KiB, the sum of the UTF-8 byte lengths of all keys and values.
    // Each value has 1021 UTF-8 bytes but 511 characters, so a count of characters would stay far below the limit.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void AcceptsObjectOf16KiB()
    {
        // 16 keys of 3 bytes and 16 values of 1021 bytes: 16 × 1024 = 16384 bytes.
        AssertValid(AgentMetadata.Validate(EntriesOf1024Bytes(lastKey: "k15")));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void RejectsObjectOf16KiBAndOneByte()
    {
        // The same with a last key of 4 bytes: 16385 bytes.
        AssertInvalid(AgentMetadata.Validate(EntriesOf1024Bytes(lastKey: "k150")));
    }

    // CONTRACT.agent-identity.md §1 makes one metadata key sent twice invalid_request.
    // A later entry with the same key would silently replace the earlier one.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void RejectsRepeatedKey()
    {
        AssertInvalid(AgentMetadata.Validate([new("hostname", "a"), new("hostname", "b")]));
    }

    // The failure detail goes to host logs, so it holds no key or value of the metadata, valid or not,
    // since an agent could otherwise write into the authority's logs.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Failure details
    [Theory]
    [MemberData(nameof(FailureNames))]
    public void FailureDetailHoldsNoKeyOrValue(string failure)
    {
        MetadataValidationResult result = AgentMetadata.Validate(Failures[failure]);

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        // oracle: spec RFC 3629 §3
        AssertInvalid(result, failure);
        Assert.DoesNotContain(LeakedKey, result.FailureDetail);
        Assert.DoesNotContain(LeakedValue, result.FailureDetail);
    }

    // The control character is part of the value, so the detail holds neither the character
    // nor its code point in a hexadecimal rendering such as U+0007, 0x07, 0x0007 or 0007.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Failure details
    [Theory]
    [MemberData(nameof(ControlCharacters))]
    public void FailureDetailDoesNotNameTheControlCharacter(int codePoint)
    {
        MetadataValidationResult result = AgentMetadata.Validate([Entry("hostname", $"host{(char)codePoint}name")]);
        string[] renderings = [$"U+{codePoint:X4}", $"0x{codePoint:X2}", $"0x{codePoint:X4}", $"{codePoint:X4}"];

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        AssertInvalid(result);
        Assert.DoesNotContain(((char)codePoint).ToString(), result.FailureDetail, StringComparison.Ordinal);
        Assert.All(
            renderings,
            rendering => Assert.DoesNotContain(rendering, result.FailureDetail, StringComparison.OrdinalIgnoreCase));
    }

    // AgentMetadata.Validate documents an ArgumentException for an entry with a null key or value.
    // A null key or value can only come from the host, since neither JSON nor protobuf metadata can hold one.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData(null, "value")]
    [InlineData("hostname", null)]
    public void ThrowsForNullKeyOrValue(string? key, string? value)
    {
        Assert.Throws<ArgumentException>(() => AgentMetadata.Validate([new(key!, value!)]));
    }

    private static AgentMetadata AssertValid(MetadataValidationResult result)
    {
        Assert.True(result.Succeeded, result.FailureDetail);

        return result.Metadata;
    }

    private static void AssertInvalid(MetadataValidationResult result, string? form = null)
    {
        Assert.False(result.Succeeded, form);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, result.Error.Code);
        Assert.Equal(400, result.Error.HttpStatusCode);
        // oracle: mutant an empty failure detail for a repeated key or for metadata over 16 KiB
        Assert.False(string.IsNullOrEmpty(result.FailureDetail));
    }

    private static KeyValuePair<string, string> Entry(string key, string value)
    {
        return new KeyValuePair<string, string>(key, value);
    }

    private static IEnumerable<KeyValuePair<string, string>> NumberedEntries(int count)
    {
        return Enumerable.Range(0, count).Select(i => new KeyValuePair<string, string>($"key_{i}", "value"));
    }

    private static IEnumerable<KeyValuePair<string, string>> EntriesOf1024Bytes(string lastKey)
    {
        string value = Repeat("\u00E9", 510) + "a";

        return Enumerable.Range(0, 15)
            .Select(i => new KeyValuePair<string, string>($"k{i:D2}", value))
            .Append(new KeyValuePair<string, string>(lastKey, value));
    }

    private static string Repeat(string unit, int count)
    {
        return string.Concat(Enumerable.Repeat(unit, count));
    }
}
