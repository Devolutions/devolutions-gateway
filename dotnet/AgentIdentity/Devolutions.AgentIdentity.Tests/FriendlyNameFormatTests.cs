namespace Devolutions.AgentIdentity.Tests;

public class FriendlyNameFormatTests
{
    // Parsed from uppercase text, so that a lowercase identity ID in a result comes from the evaluation.
    private static readonly Guid IdentityId = Guid.Parse("0F8FAD5B-D9CB-469F-A165-70867728950E");

    private const string TokenName = "Fleet";

    // A value for each known metadata key of CONTRACT.md §3.
    private static readonly Dictionary<string, string> Metadata = new()
    {
        ["hostname"] = "pc-042",
        ["fqdn"] = "pc-042.corp.example",
        ["domain"] = "corp.example",
        ["os_name"] = "Windows",
        ["os_version"] = "10.0.26100",
        ["arch"] = "x86_64",
        ["agent_version"] = "2026.3.0",
        ["machine_id"] = "4c4c4544-0042-3510-8052-b4c04f4a4e32",
    };

    // INTENT.agent-identity.md, "Enrollment": the placeholders are `{<known metadata key>}` and `{token_name}`,
    // the enrollment token's name; CONTRACT.md §3 lists the known metadata keys.
    [Theory]
    [InlineData("{hostname}", "pc-042")]
    [InlineData("{fqdn}", "pc-042.corp.example")]
    [InlineData("{domain}", "corp.example")]
    [InlineData("{os_name}", "Windows")]
    [InlineData("{os_version}", "10.0.26100")]
    [InlineData("{arch}", "x86_64")]
    [InlineData("{agent_version}", "2026.3.0")]
    [InlineData("{machine_id}", "4c4c4544-0042-3510-8052-b4c04f4a4e32")]
    [InlineData("{token_name}", "Fleet")]
    public void EvaluatesEachPlaceholderToItsValue(string format, string expected)
    {
        Assert.Equal(expected, Evaluate(format));
    }

    // INTENT.agent-identity.md, "Enrollment": `{{` and `}}` escape braces, and other text is literal.
    [Theory]
    [InlineData("{{", "{")]
    [InlineData("}}", "}")]
    [InlineData("}}{{", "}{")]
    [InlineData("{{hostname}}", "{hostname}")]
    [InlineData("{{{hostname}}}", "{pc-042}")]
    [InlineData("Laptop {hostname} ({os_name}, {arch})", "Laptop pc-042 (Windows, x86_64)")]
    [InlineData("{token_name}/{hostname}{hostname}", "Fleet/pc-042pc-042")]
    public void EvaluatesLiteralTextAndEscapedBraces(string format, string expected)
    {
        Assert.Equal(expected, Evaluate(format));
    }

    // INTENT.agent-identity.md, "Enrollment": a format with an unpaired brace or an unknown placeholder is rejected.
    // A placeholder names a known metadata key of CONTRACT.md §3 or `token_name` exactly,
    // so another case, white space or another key, such as one that §3 allows but does not list, is unknown.
    [Theory]
    [InlineData("{")]
    [InlineData("}")]
    [InlineData("{hostname")]
    [InlineData("hostname}")]
    [InlineData("{hostname}}")]
    [InlineData("{{hostname}")]
    [InlineData("{{hostname}}}")]
    [InlineData("{{}")]
    [InlineData("}{")]
    [InlineData("{}")]
    [InlineData("{Hostname}")]
    [InlineData("{HOSTNAME}")]
    [InlineData("{ hostname }")]
    [InlineData("{hostname }")]
    [InlineData("{host{name}")]
    [InlineData("{token}")]
    [InlineData("{name}")]
    [InlineData("{custom_key}")]
    [InlineData("{0}")]
    public void TryParseRejectsAnUnpairedBraceOrAnUnknownPlaceholder(string format)
    {
        Assert.False(FriendlyNameFormat.TryParse(format, out FriendlyNameFormat? parsed, out string? error));
        Assert.Null(parsed);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    // INTENT.agent-identity.md, "Enrollment": a missing metadata value evaluates to empty.
    [Fact]
    public void EvaluatesAMissingMetadataValueToEmpty()
    {
        Dictionary<string, string> metadata = new() { ["hostname"] = "pc-042", ["arch"] = "x86_64" };

        Assert.Equal("pc-042..x86_64", Evaluate("{hostname}.{domain}.{arch}", metadata));
    }

    // `{token_name}` is the enrollment token's name,
    // and CONTRACT.md §3 lets an agent report an unknown key such as `token_name`, which is never used for anything.
    [Fact]
    public void EvaluatesTokenNameToTheTokenNameRatherThanAReportedValue()
    {
        Dictionary<string, string> metadata = new(Metadata) { ["token_name"] = "Reported" };

        Assert.Equal("Fleet", Evaluate("{token_name}", metadata));
    }

    // A value is substituted once, so braces that a device reports are text, not placeholders.
    [Fact]
    public void EvaluatesBracesInAValueAsText()
    {
        Dictionary<string, string> metadata = new() { ["hostname"] = "{token_name}}}" };

        Assert.Equal("{token_name}}}", Evaluate("{hostname}", metadata));
    }

    // The White_Space code points of Unicode PropList.txt (18.0.0):
    // 0009..000D, 0020, 0085, 00A0, 1680, 2000..200A, 2028, 2029, 202F, 205F and 3000; 25 code points in all.
    private static readonly int[] WhiteSpace =
    [
        0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0, 0x1680,
        0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
        0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
    ];

    public static TheoryData<int> WhiteSpaceRows => new(WhiteSpace);

    // INTENT.agent-identity.md, "Enrollment": the result is trimmed of Unicode `White_Space`.
    [Theory]
    [MemberData(nameof(WhiteSpaceRows))]
    public void TrimsAWhiteSpaceCodePointFromBothEnds(int codePoint)
    {
        string space = char.ConvertFromUtf32(codePoint);

        Assert.Equal("pc 042", Evaluate("{token_name}", tokenName: space + space + "pc 042" + space));
    }

    // No code point outside `White_Space` is trimmed, such as U+180E MONGOLIAN VOWEL SEPARATOR,
    // which left `White_Space` in Unicode 6.3, U+200B ZERO WIDTH SPACE and U+FEFF ZERO WIDTH NO-BREAK SPACE.
    // Every other scalar value of the Basic Multilingual Plane is checked, and a few beyond it.
    [Fact]
    public void KeepsEveryOtherCodePointAtBothEnds()
    {
        IEnumerable<int> others = Enumerable.Range(0, 0x10000)
            .Where(codePoint => !(0xD800 <= codePoint && codePoint <= 0xDFFF) && !WhiteSpace.Contains(codePoint))
            .Concat([0x1F600, 0xE0020, 0x10FFFF]);

        List<string> trimmed = [];

        foreach (int codePoint in others)
        {
            string text = char.ConvertFromUtf32(codePoint);

            if (Evaluate("{token_name}", tokenName: text + "x" + text) != text + "x" + text)
            {
                trimmed.Add($"U+{codePoint:X4}");
            }
        }

        Assert.Empty(trimmed);
    }

    // INTENT.agent-identity.md, "Enrollment": the result is truncated to 255 Unicode scalar values
    // without splitting one.
    // U+1F600 is one scalar value that UTF-16 writes as a surrogate pair, so a cut by UTF-16 code unit would split it,
    // and U+0301 COMBINING ACUTE ACCENT is a scalar value of its own.
    public static TheoryData<string, string> TruncationRows => new()
    {
        { new string('a', 255), new string('a', 255) },
        { new string('a', 256), new string('a', 255) },
        { new string('a', 254) + "\U0001F600b", new string('a', 254) + "\U0001F600" },
        { new string('a', 255) + "\U0001F600", new string('a', 255) },
        { Repeat("\U0001F600", 300), Repeat("\U0001F600", 255) },
        { Repeat("e\u0301", 200), Repeat("e\u0301", 127) + "e" },
    };

    [Theory]
    [MemberData(nameof(TruncationRows))]
    public void TruncatesTo255ScalarValues(string tokenName, string expected)
    {
        Assert.Equal(expected, Evaluate("{token_name}", tokenName: tokenName));
    }

    // INTENT.agent-identity.md, "Enrollment": the result is trimmed, truncated and trimmed again,
    // so a stored name never starts or ends with white space.
    [Fact]
    public void TrimsTheWhiteSpaceThatTruncationLeavesAtTheEnd()
    {
        string tokenName = new string('a', 250) + new string(' ', 10) + "bbbbb";

        Assert.Equal(new string('a', 250), Evaluate("{token_name}", tokenName: tokenName));
    }

    // Leading white space is trimmed before truncation, so it never takes the place of a kept scalar value.
    [Fact]
    public void TrimsBeforeTruncating()
    {
        string tokenName = "\u3000" + new string(' ', 9) + new string('a', 255);

        Assert.Equal(new string('a', 255), Evaluate("{token_name}", tokenName: tokenName));
    }

    // INTENT.agent-identity.md, "Enrollment": an empty result falls back to the identity ID,
    // which CONTRACT.md §1 writes as a lowercase hyphenated UUID.
    [Theory]
    [InlineData("{fqdn}", TokenName)]
    [InlineData("", TokenName)]
    [InlineData(" \t\u00A0", TokenName)]
    [InlineData("{token_name}", "\u2028\u3000")]
    public void FallsBackToTheIdentityIdForAnEmptyName(string format, string tokenName)
    {
        Dictionary<string, string> metadata = new() { ["hostname"] = "pc-042" };

        Assert.Equal("0f8fad5b-d9cb-469f-a165-70867728950e", Evaluate(format, metadata, tokenName));
    }

    // A lone surrogate is no Unicode scalar value, so it counts as one U+FFFD REPLACEMENT CHARACTER,
    // which Unicode §3.9 recommends for an ill-formed code unit, and the name stays well-formed UTF-16.
    [Fact]
    public void ReplacesALoneSurrogateWithTheReplacementCharacter()
    {
        Assert.Equal("\uFFFDpc", Evaluate("{token_name}", tokenName: "\uD83Dpc"));
        Assert.Equal("pc\uFFFD", Evaluate("{token_name}", tokenName: "pc\uDE00"));
        Assert.Equal("\uFFFD\uFFFD", Evaluate("{token_name}", tokenName: "\uDE00\uD83D"));
        Assert.Equal("pc\uFFFD", Evaluate("pc\uD83D", tokenName: string.Empty));
    }

    // INTENT.agent-identity.md, "Enrollment": the default format is `{hostname}`.
    [Fact]
    public void DefaultFormatIsTheHostname()
    {
        Assert.Equal("{hostname}", FriendlyNameFormat.Default.ToString());
        Assert.Equal("pc-042", FriendlyNameFormat.Default.Evaluate(Metadata, TokenName, IdentityId));
    }

    // The authority stores the format text with the token and parses it again at each enrollment.
    [Fact]
    public void ToStringReturnsTheParsedText()
    {
        const string format = "{{{token_name}}} {hostname}";

        Assert.True(FriendlyNameFormat.TryParse(format, out FriendlyNameFormat? parsed, out _));
        Assert.Equal(format, parsed.ToString());
    }

    [Fact]
    public void TryParseRejectsANullFormat()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => FriendlyNameFormat.TryParse(null!, out _, out _));

        Assert.Equal("format", exception.ParamName);
    }

    [Fact]
    public void EvaluateRejectsNullMetadata()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => FriendlyNameFormat.Default.Evaluate(null!, TokenName, IdentityId));

        Assert.Equal("metadata", exception.ParamName);
    }

    [Fact]
    public void EvaluateRejectsANullTokenName()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => FriendlyNameFormat.Default.Evaluate(Metadata, null!, IdentityId));

        Assert.Equal("tokenName", exception.ParamName);
    }

    private static string Evaluate(
        string format,
        IReadOnlyDictionary<string, string>? metadata = null,
        string tokenName = TokenName)
    {
        Assert.True(FriendlyNameFormat.TryParse(format, out FriendlyNameFormat? parsed, out string? error), error);

        return parsed.Evaluate(metadata ?? Metadata, tokenName, IdentityId);
    }

    private static string Repeat(string text, int count)
    {
        return string.Concat(Enumerable.Repeat(text, count));
    }
}
