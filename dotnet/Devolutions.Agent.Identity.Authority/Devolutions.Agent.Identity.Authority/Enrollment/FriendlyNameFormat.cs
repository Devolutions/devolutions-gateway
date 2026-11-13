using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The format from which the authority creates an identity's friendly name once, at enrollment.
/// </summary>
/// <remarks>
/// <para>
/// A format is text with placeholders: <c>{hostname}</c>, <c>{fqdn}</c>, <c>{domain}</c>, <c>{os_name}</c>,
/// <c>{os_version}</c>, <c>{arch}</c>, <c>{agent_version}</c>, <c>{machine_id}</c>, <c>{key_storage}</c> and
/// <c>{key_storage_available}</c> for the reported metadata,
/// and <c>{token_name}</c> for the name of the enrollment token.
/// <c>{{</c> and <c>}}</c> write a literal brace.
/// The name is never sent to the agent, and later metadata updates never rename the identity.
/// </para>
/// <para>
/// A format is administrator input that may hold a pasted token, which never appears in logs,
/// so a parse error and <see cref="ToString"/> never hold any part of the format text.
/// Only <see cref="Evaluate"/> returns its literal text, by design, as part of the friendly name.
/// The host stores the text that it parsed with the token.
/// </para>
/// </remarks>
public sealed class FriendlyNameFormat
{
    // The known metadata keys of CONTRACT.agent-identity.md §3, and the token's name.
    private static readonly string[] Placeholders =
    [
        "hostname", "fqdn", "domain", "os_name", "os_version", "arch", "agent_version", "machine_id", "key_storage",
        "key_storage_available", "token_name",
    ];

    // Ends every parse error without repeating the format text.
    private static readonly string ErrorGuidance =
        " The placeholders are "
        + string.Join(", ", Placeholders[..^1].Select(placeholder => "{" + placeholder + "}"))
        + " and {" + Placeholders[^1] + "}, and '{{' and '}}' write literal braces.";

    private const string TokenNamePlaceholder = "token_name";

    private const int MaxScalarValues = 255;

    private readonly Segment[] _segments;

    private FriendlyNameFormat(Segment[] segments)
    {
        _segments = segments;
    }

    /// <summary>
    /// The format of a token created without one: <c>{hostname}</c>.
    /// </summary>
    public static FriendlyNameFormat Default { get; } = new([new Segment("hostname", true)]);

    /// <summary>
    /// Parses a format, which the authority does when an administrator creates a token with it.
    /// </summary>
    /// <param name="format">The format text.</param>
    /// <param name="result">The format, when the text is valid.</param>
    /// <param name="error">
    /// Why the text is invalid, for the administrator: an unpaired brace or an unknown placeholder,
    /// its position counted in Unicode scalar values from 1, and the valid placeholders.
    /// The error holds no part of the format text.
    /// </param>
    /// <returns>Whether the text is a valid format.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="format"/> is null.</exception>
    public static bool TryParse(
        string format,
        [NotNullWhen(true)] out FriendlyNameFormat? result,
        [NotNullWhen(false)] out string? error)
    {
        ArgumentNullException.ThrowIfNull(format);

        List<Segment> segments = [];
        string? problem = ParseSegments(format, segments);

        if (problem is not null)
        {
            result = null;
            error = problem;

            return false;
        }

        result = new FriendlyNameFormat([.. segments]);
        error = null;

        return true;
    }

    /// <summary>
    /// Evaluates the friendly name of a new identity.
    /// </summary>
    /// <remarks>
    /// Each placeholder takes its value, and a missing metadata value is empty.
    /// The result is trimmed of Unicode <c>White_Space</c>,
    /// truncated to 255 Unicode scalar values without splitting one, and trimmed again,
    /// so a name never starts or ends with white space.
    /// A lone surrogate is no scalar value, so it becomes U+FFFD REPLACEMENT CHARACTER.
    /// An empty result falls back to the identity ID.
    /// </remarks>
    /// <param name="metadata">The metadata that the enroll request reports, as its body parser validated it.</param>
    /// <param name="tokenName">The name of the token that the request presents.</param>
    /// <param name="identityId">The ID of the new identity.</param>
    /// <returns>The friendly name, or the identity ID in lowercase hyphenated form.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="metadata"/> or <paramref name="tokenName"/> is null.
    /// </exception>
    public string Evaluate(AgentMetadata metadata, string tokenName, Guid identityId)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(tokenName);

        StringBuilder text = new();

        foreach (Segment segment in _segments)
        {
            if (!segment.IsPlaceholder)
            {
                text.Append(segment.Text);
            }
            else if (segment.Text == TokenNamePlaceholder)
            {
                text.Append(tokenName);
            }
            else if (metadata.TryGetValue(segment.Text, out string? value))
            {
                text.Append(value);
            }
        }

        string name = Truncate(text.ToString().Trim()).Trim();

        return name.Length == 0 ? identityId.ToString("D") : name;
    }

    /// <summary>
    /// Returns the type name, never the format text, which may hold a pasted token.
    /// </summary>
    public override string ToString()
    {
        return nameof(FriendlyNameFormat);
    }

    // Adds the segments of the format, or returns why the format is invalid.
    private static string? ParseSegments(string format, List<Segment> segments)
    {
        StringBuilder literal = new();
        int position = 0;

        while (position < format.Length)
        {
            char c = format[position];

            if ((c == '{' || c == '}') && position + 1 < format.Length && format[position + 1] == c)
            {
                literal.Append(c);
                position += 2;
            }
            else if (c == '{')
            {
                int end = format.IndexOf('}', position + 1);

                if (end < 0)
                {
                    return ParseError("an unpaired '{'", format, position);
                }

                string name = format[(position + 1)..end];

                if (!Placeholders.Contains(name, StringComparer.Ordinal))
                {
                    return ParseError("an unknown placeholder", format, position);
                }

                segments.Add(new Segment(literal.ToString(), false));
                literal.Clear();
                segments.Add(new Segment(name, true));
                position = end + 1;
            }
            else if (c == '}')
            {
                return ParseError("an unpaired '}'", format, position);
            }
            else
            {
                literal.Append(c);
                position++;
            }
        }

        segments.Add(new Segment(literal.ToString(), false));

        return null;
    }

    // Says what is wrong and where, without any part of the format text.
    // The position counts Unicode scalar values from 1, as an administrator counts characters,
    // and a lone surrogate counts as one.
    private static string ParseError(string problem, string format, int index)
    {
        int character = 1;
        ReadOnlySpan<char> before = format.AsSpan(0, index);

        while (!before.IsEmpty)
        {
            Rune.DecodeFromUtf16(before, out _, out int consumed);
            before = before[consumed..];
            character++;
        }

        return "The format has " + problem + " at character " + character.ToString(CultureInfo.InvariantCulture) + "."
            + ErrorGuidance;
    }

    // Keeps the first 255 Unicode scalar values, so that a surrogate pair is kept or dropped whole.
    private static string Truncate(ReadOnlySpan<char> text)
    {
        StringBuilder truncated = new();
        Span<char> utf16 = stackalloc char[2];

        for (int count = 0; count < MaxScalarValues && !text.IsEmpty; count++)
        {
            // An invalid code unit decodes to U+FFFD and is consumed alone.
            Rune.DecodeFromUtf16(text, out Rune scalar, out int consumed);
            truncated.Append(utf16[..scalar.EncodeToUtf16(utf16)]);
            text = text[consumed..];
        }

        return truncated.ToString();
    }

    // Literal text, or the name of a placeholder.
    private readonly record struct Segment(string Text, bool IsPlaceholder);
}
