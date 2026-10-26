namespace Devolutions.Agent.Identity.Authority.Tests;

public class FriendlyNameFormatTests
{
    // Parsed from uppercase text, so that a lowercase identity ID in a result comes from the evaluation.
    private static readonly Guid IdentityId = Guid.Parse("0F8FAD5B-D9CB-469F-A165-70867728950E");

    private const string TokenName = "Fleet";

    // A dvaet1 token for https://host/dvls (CONTRACT.agent-identity.md §2),
    // which an administrator might paste into a format.
    private const string Bag = "eyJ1IjoiaHR0cHM6Ly9ob3N0L2R2bHMifQ";
    private const string Secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    private const string Token = "dvaet1." + Bag + "." + Secret;

    // The placeholders of INTENT.agent-identity.md, "Enrollment":
    // the known metadata keys of CONTRACT.agent-identity.md §3, and the token's name.
    private static readonly string[] Placeholders =
    [
        "{hostname}", "{fqdn}", "{domain}", "{os_name}", "{os_version}", "{arch}", "{agent_version}", "{machine_id}",
        "{token_name}",
    ];

    // A value for each known metadata key of CONTRACT.agent-identity.md §3.
    private static readonly AgentMetadata Metadata = Validated(new Dictionary<string, string>
    {
        ["hostname"] = "pc-042",
        ["fqdn"] = "pc-042.corp.example",
        ["domain"] = "corp.example",
        ["os_name"] = "Windows",
        ["os_version"] = "10.0.26100",
        ["arch"] = "x86_64",
        ["agent_version"] = "2026.3.0",
        ["machine_id"] = "4c4c4544-0042-3510-8052-b4c04f4a4e32",
    });

    // INTENT.agent-identity.md, "Enrollment": the placeholders are `{<known metadata key>}` and `{token_name}`,
    // the enrollment token's name; CONTRACT.agent-identity.md §3 lists the known metadata keys.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{hostname}", "pc-042")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{fqdn}", "pc-042.corp.example")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{domain}", "corp.example")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{os_name}", "Windows")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{os_version}", "10.0.26100")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{arch}", "x86_64")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{agent_version}", "2026.3.0")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{machine_id}", "4c4c4544-0042-3510-8052-b4c04f4a4e32")]
    [InlineData("{token_name}", "Fleet")]
    // `{{` and `}}` escape braces, and other text is literal.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [InlineData("{{", "{")]
    [InlineData("}}", "}")]
    [InlineData("}}{{", "}{")]
    [InlineData("{{hostname}}", "{hostname}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{{{hostname}}}", "{pc-042}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("Laptop {hostname} ({os_name}, {arch})", "Laptop pc-042 (Windows, x86_64)")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{token_name}/{hostname}{hostname}", "Fleet/pc-042pc-042")]
    public void EvaluatesThePlaceholdersAndTheLiteralText(string format, string expected)
    {
        Assert.Equal(expected, Evaluate(format));
    }

    // INTENT.agent-identity.md, "Enrollment": a format with an unpaired brace or an unknown placeholder is rejected.
    // A placeholder names a known metadata key of CONTRACT.agent-identity.md §3 or `token_name` exactly,
    // so another case, white space or another key, such as one that §3 allows but does not list, is unknown.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{Hostname}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{HOSTNAME}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{ hostname }")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{hostname }")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{host{name}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{token}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{name}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{custom_key}")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [InlineData("{0}")]
    public void TryParseRejectsAnUnpairedBraceOrAnUnknownPlaceholder(string format)
    {
        Assert.False(FriendlyNameFormat.TryParse(format, out _, out _));
    }

    // The error says where the problem is, counting Unicode scalar values from 1,
    // so that U+1F600, which UTF-16 writes as two code units, counts as one character.
    // oracle: mutant a parse error that leaves out the position of the problem,
    // or gives a position that does not count up from 1
    [Theory]
    [InlineData("{", 1)]
    [InlineData("ab}", 3)]
    [InlineData("{hostname} {", 12)]
    [InlineData("{{x}}}", 6)]
    [InlineData("x{Hostname}", 2)]
    [InlineData("\U0001F600{", 2)]
    [InlineData("\U0001F600\U0001F600 {Hostname}", 4)]
    public void TryParseErrorGivesThePositionOfTheProblem(string format, int position)
    {
        Assert.False(FriendlyNameFormat.TryParse(format, out _, out string? error));
        Assert.Matches($@"\bcharacter {position}\b", error);
    }

    // Every error lists the placeholders, so that the administrator can correct the format.
    // oracle: mutant a parse error that lists a placeholder without one of its braces
    [Theory]
    [InlineData("{")]
    [InlineData("}")]
    [InlineData("{Hostname}")]
    public void TryParseErrorListsThePlaceholders(string format)
    {
        Assert.False(FriendlyNameFormat.TryParse(format, out _, out string? error));

        foreach (string placeholder in Placeholders)
        {
            Assert.Contains(placeholder, error, StringComparison.Ordinal);
        }
    }

    // Security invariant 9: tokens never appear in logs, not even partially.
    // A format is administrator input that may hold a pasted token, and a host may log why a format was refused.
    // Each row holds the token in an unknown placeholder, or as literal text before each kind of error.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Theory]
    [InlineData("in an unknown placeholder", "{" + Token + "}")]
    [InlineData("before an unknown placeholder", "{hostname} " + Token + " {Hostname}")]
    [InlineData("before an unpaired opening brace", "{hostname} " + Token + " {")]
    [InlineData("before an unpaired closing brace", Token + "}")]
    public void TryParseErrorRevealsNoPartOfTheFormat(string name, string format)
    {
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
        Assert.False(FriendlyNameFormat.TryParse(format, out _, out string? error), name);
        EnrollmentTokenAssert.RevealsNoPart(error, Bag, Secret);
    }

    // Security invariant 9: tokens never appear in logs, not even partially.
    // A log statement may format the object of a valid format that holds a pasted token as literal text.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Fact]
    public void ToStringRevealsNoPartOfTheFormat()
    {
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
        Assert.True(
            FriendlyNameFormat.TryParse("{hostname} " + Token, out FriendlyNameFormat? parsed, out string? error),
            error);

        EnrollmentTokenAssert.RevealsNoPart($"{parsed}", Bag, Secret);
    }

    // A missing metadata value evaluates to empty.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [Fact]
    public void EvaluatesAMissingMetadataValueToEmpty()
    {
        AgentMetadata metadata =
            Validated(new Dictionary<string, string> { ["hostname"] = "pc-042", ["arch"] = "x86_64" });

        Assert.Equal("pc-042..x86_64", Evaluate("{hostname}.{domain}.{arch}", metadata));
    }

    // `{token_name}` is the enrollment token's name,
    // and CONTRACT.agent-identity.md §3 lets an agent report an unknown key such as `token_name`,
    // which is never used for authorization.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [Fact]
    public void EvaluatesTokenNameToTheTokenNameRatherThanAReportedValue()
    {
        AgentMetadata metadata = Validated(new Dictionary<string, string>(Metadata) { ["token_name"] = "Reported" });

        Assert.Equal("Fleet", Evaluate("{token_name}", metadata));
    }

    // The format holds the placeholders and the escaped braces, and a placeholder evaluates to its value.
    // A value is substituted once, so braces that a device reports are text, not placeholders.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [Fact]
    public void EvaluatesBracesInAValueAsText()
    {
        AgentMetadata metadata = Validated(new Dictionary<string, string> { ["hostname"] = "{token_name}}}" });

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

    // The result is trimmed of Unicode `White_Space`.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    // oracle: spec Unicode PropList.txt §White_Space
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
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    // oracle: spec Unicode PropList.txt §White_Space
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

    // INTENT.agent-identity.md, "Enrollment": the result is trimmed, truncated to 255 Unicode scalar values
    // without splitting one, and trimmed again, so a stored name never starts or ends with white space.
    // U+1F600 is one scalar value that UTF-16 writes as a surrogate pair, so a cut by UTF-16 code unit would split it,
    // and U+0301 COMBINING ACUTE ACCENT is a scalar value of its own.
    // Leading white space is trimmed before truncation, so it never takes the place of a kept scalar value.
    private static Dictionary<string, (string Value, string Expected)> TokenNamesToTruncate => new()
    {
        ["255 letters"] = (new string('a', 255), new string('a', 255)),
        ["256 letters"] = (new string('a', 256), new string('a', 255)),
        ["an emoji at the cut"] = (new string('a', 254) + "\U0001F600b", new string('a', 254) + "\U0001F600"),
        ["an emoji after the cut"] = (new string('a', 255) + "\U0001F600", new string('a', 255)),
        ["300 emoji"] = (Repeat("\U0001F600", 300), Repeat("\U0001F600", 255)),
        ["200 accented letters"] = (Repeat("e\u0301", 200), Repeat("e\u0301", 127) + "e"),
        // oracle: spec Unicode PropList.txt §White_Space
        ["white space at the cut"] = (new string('a', 250) + new string(' ', 10) + "bbbbb", new string('a', 250)),
        // oracle: spec Unicode PropList.txt §White_Space
        ["white space before 255 letters"] =
            ("\u3000" + new string(' ', 9) + new string('a', 255), new string('a', 255)),
    };

    public static TheoryData<string> TokenNamesToTruncateNames => new(TokenNamesToTruncate.Keys);

    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [Theory]
    [MemberData(nameof(TokenNamesToTruncateNames))]
    public void TruncatesTo255ScalarValuesBetweenTwoTrims(string tokenName)
    {
        (string value, string expected) = TokenNamesToTruncate[tokenName];

        Assert.Equal(expected, Evaluate("{token_name}", tokenName: value));
    }

    // INTENT.agent-identity.md, "Enrollment": an empty result falls back to the identity ID,
    // which CONTRACT.agent-identity.md §1 writes as a lowercase hyphenated UUID.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData("{fqdn}", TokenName)]
    [InlineData("", TokenName)]
    // oracle: spec Unicode PropList.txt §White_Space
    [InlineData(" \t\u00A0", TokenName)]
    // oracle: spec Unicode PropList.txt §White_Space
    [InlineData("{token_name}", "\u2028\u3000")]
    public void FallsBackToTheIdentityIdForAnEmptyName(string format, string tokenName)
    {
        AgentMetadata metadata = Validated(new Dictionary<string, string> { ["hostname"] = "pc-042" });

        Assert.Equal("0f8fad5b-d9cb-469f-a165-70867728950e", Evaluate(format, metadata, tokenName));
    }

    // The default format is `{hostname}`.
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Enrollment
    [Fact]
    public void DefaultFormatIsTheHostname()
    {
        AgentMetadata withoutHostname = Validated(new Dictionary<string, string> { ["fqdn"] = "pc-042.corp.example" });

        Assert.Equal("pc-042", FriendlyNameFormat.Default.Evaluate(Metadata, TokenName, IdentityId));
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        Assert.Equal(
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            FriendlyNameFormat.Default.Evaluate(withoutHostname, TokenName, IdentityId));
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Fact]
    public void TryParseRejectsANullFormat()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => FriendlyNameFormat.TryParse(null!, out _, out _));

        Assert.Equal("format", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Theory]
    [InlineData("metadata")]
    [InlineData("tokenName")]
    public void EvaluateRejectsANullArgument(string parameter)
    {
        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(EvaluationsWithANullArgument[parameter]);

        Assert.Equal(parameter, exception.ParamName);
    }

    // An evaluation with one null argument, by the name of the parameter that receives it.
    private static Dictionary<string, Action> EvaluationsWithANullArgument => new()
    {
        ["metadata"] = () => FriendlyNameFormat.Default.Evaluate(null!, TokenName, IdentityId),
        ["tokenName"] = () => FriendlyNameFormat.Default.Evaluate(Metadata, null!, IdentityId),
    };

    private static string Evaluate(string format, AgentMetadata? metadata = null, string tokenName = TokenName)
    {
        Assert.True(FriendlyNameFormat.TryParse(format, out FriendlyNameFormat? parsed, out string? error), error);

        return parsed.Evaluate(metadata ?? Metadata, tokenName, IdentityId);
    }

    // Evaluate takes only validated metadata, as the request body parsers produce it.
    private static AgentMetadata Validated(IEnumerable<KeyValuePair<string, string>> entries)
    {
        MetadataValidationResult result = AgentMetadata.Validate(entries);
        Assert.True(result.Succeeded, result.FailureDetail);

        return result.Metadata;
    }

    private static string Repeat(string text, int count)
    {
        return string.Concat(Enumerable.Repeat(text, count));
    }
}
