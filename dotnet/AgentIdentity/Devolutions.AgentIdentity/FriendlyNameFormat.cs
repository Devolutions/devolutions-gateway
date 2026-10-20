using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The format from which the authority creates an identity's friendly name once, at enrollment.
/// </summary>
/// <remarks>
/// A format is text with placeholders: <c>{hostname}</c>, <c>{fqdn}</c>, <c>{domain}</c>, <c>{os_name}</c>,
/// <c>{os_version}</c>, <c>{arch}</c>, <c>{agent_version}</c> and <c>{machine_id}</c> for the reported metadata,
/// and <c>{token_name}</c> for the name of the enrollment token.
/// <c>{{</c> and <c>}}</c> write a literal brace.
/// The name is never sent to the agent, and later metadata updates never rename the identity.
/// </remarks>
public sealed class FriendlyNameFormat
{
    // The known metadata keys of CONTRACT.md §3, and the token's name.
    private static readonly string[] Placeholders =
        ["hostname", "fqdn", "domain", "os_name", "os_version", "arch", "agent_version", "machine_id", "token_name"];

    private const string TokenNamePlaceholder = "token_name";

    private const int MaxScalarValues = 255;

    private readonly string _format;
    private readonly Segment[] _segments;

    private FriendlyNameFormat(string format, Segment[] segments)
    {
        _format = format;
        _segments = segments;
    }

    /// <summary>
    /// The format that a token without one uses: <c>{hostname}</c>.
    /// </summary>
    public static FriendlyNameFormat Default { get; } = new("{hostname}", [new Segment("hostname", true)]);

    /// <summary>
    /// Parses a format, which the authority does when an administrator creates a token with it.
    /// </summary>
    /// <param name="format">The format text.</param>
    /// <param name="result">The format, when the text is valid.</param>
    /// <param name="error">
    /// Why the text is invalid, for the administrator: an unpaired brace or an unknown placeholder.
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

        result = new FriendlyNameFormat(format, [.. segments]);
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
    /// <param name="metadata">The metadata that the enroll request reports.</param>
    /// <param name="tokenName">The name of the token that the request presents.</param>
    /// <param name="identityId">The ID of the new identity.</param>
    /// <returns>The friendly name, or the identity ID in lowercase hyphenated form.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="metadata"/> or <paramref name="tokenName"/> is null.
    /// </exception>
    public string Evaluate(IReadOnlyDictionary<string, string> metadata, string tokenName, Guid identityId)
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
    /// Returns the format text, which the authority stores with the token.
    /// </summary>
    public override string ToString()
    {
        return _format;
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
                    return "The format has a '{' without a matching '}'; write '{{' for a literal '{'.";
                }

                string name = format[(position + 1)..end];

                if (!Placeholders.Contains(name, StringComparer.Ordinal))
                {
                    return "The format has the unknown placeholder '{" + name + "}'; the placeholders are "
                        + string.Join(", ", Placeholders.Select(placeholder => "{" + placeholder + "}")) + ".";
                }

                segments.Add(new Segment(literal.ToString(), false));
                literal.Clear();
                segments.Add(new Segment(name, true));
                position = end + 1;
            }
            else if (c == '}')
            {
                return "The format has a '}' without a matching '{'; write '}}' for a literal '}'.";
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
