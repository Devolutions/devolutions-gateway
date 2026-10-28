using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Parses RFC 8941 structured field dictionaries, and serializes the values that a signature base holds.
/// </summary>
/// <remarks>
/// Parsing follows RFC 8941 §4.2, except that a repeated dictionary key or parameter key fails it.
/// RFC 8941 keeps the last of repeated keys,
/// so a field that repeats one could be read differently by a proxy, a log or another parser.
/// A byte sequence keeps its base64 text, so that the caller decodes it as strictly as its protocol requires.
/// </remarks>
internal static class StructuredField
{
    /// <summary>
    /// Parses a field value as a dictionary.
    /// </summary>
    /// <param name="input">The field value, with all its field lines combined.</param>
    /// <param name="dictionary">
    /// The members in received order, when the value is a dictionary without repeated keys.
    /// </param>
    public static bool TryParseDictionary(
        string input,
        [NotNullWhen(true)] out IReadOnlyList<DictionaryMember>? dictionary)
    {
        dictionary = null;

        // RFC 8941 §4.2 step 1: a value that is not ASCII fails parsing.
        if (!Ascii.IsValid(input))
        {
            return false;
        }

        Reader reader = new(input);
        reader.SkipSpaces();

        // The dictionary rule consumes trailing white space and fails on anything else,
        // so the input is empty when it succeeds.
        if (!reader.TryParseDictionary(out List<DictionaryMember>? members))
        {
            return false;
        }

        dictionary = members;
        return true;
    }

    /// <summary>
    /// Serializes a string, as RFC 8941 §4.1.6 does.
    /// </summary>
    /// <param name="value">
    /// A string of printable ASCII characters, such as one that <see cref="TryParseDictionary"/> produced.
    /// </param>
    public static string SerializeString(string value)
    {
        StringBuilder builder = new(value.Length + 2);
        builder.Append('"');

        foreach (char c in value)
        {
            if (c is '"' or '\\')
            {
                builder.Append('\\');
            }

            builder.Append(c);
        }

        return builder.Append('"').ToString();
    }

    /// <summary>
    /// Serializes an integer, as RFC 8941 §4.1.4 does.
    /// </summary>
    /// <param name="value">
    /// An integer of at most 15 digits, such as one that <see cref="TryParseDictionary"/> produced.
    /// </param>
    public static string SerializeInteger(long value)
    {
        return value.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Tells whether a value is an RFC 9110 token, such as a request method.
    /// </summary>
    public static bool IsToken(string value)
    {
        return value.Length > 0 && value.All(IsTokenCharacter);
    }

    // RFC 9110 §5.6.2: tchar.
    private static bool IsTokenCharacter(char c)
    {
        return char.IsAsciiLetterOrDigit(c)
            || c is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|'
                or '~';
    }

    /// <summary>
    /// A value without parameters: an integer, a decimal, a string, a token, a byte sequence or a Boolean.
    /// </summary>
    public abstract record BareItem;

    public sealed record IntegerItem(long Value) : BareItem;

    public sealed record DecimalItem(decimal Value) : BareItem;

    public sealed record StringItem(string Value) : BareItem;

    public sealed record TokenItem(string Value) : BareItem;

    /// <param name="Base64">
    /// The text between the colons, which holds only base64 characters but may not be canonical.
    /// </param>
    public sealed record ByteSequenceItem(string Base64) : BareItem;

    public sealed record BooleanItem(bool Value) : BareItem;

    public sealed record Parameter(string Key, BareItem Value);

    /// <summary>
    /// The value of a dictionary member: an item or an inner list.
    /// </summary>
    public abstract record MemberValue;

    public sealed record Item(BareItem Value, IReadOnlyList<Parameter> Parameters) : MemberValue;

    public sealed record InnerList(IReadOnlyList<Item> Items, IReadOnlyList<Parameter> Parameters) : MemberValue;

    public sealed record DictionaryMember(string Key, MemberValue Value);

    /// <summary>
    /// The parsing algorithms of RFC 8941 §4.2, each consuming the input from the current position.
    /// </summary>
    /// <remarks>
    /// UNTESTED: parsing takes time linear in the length of the input.
    /// The input is an unauthenticated header,
    /// so a quadratic step would let one request cost a quadratic amount of work.
    /// When changing a rule, keep each key lookup a set lookup and read each character a bounded number of times.
    /// </remarks>
    private sealed class Reader(string input)
    {
        private int _position;

        private bool AtEnd => _position == input.Length;

        public void SkipSpaces()
        {
            while (Next(' '))
            {
                _position++;
            }
        }

        // RFC 8941 §4.2.2.
        public bool TryParseDictionary([NotNullWhen(true)] out List<DictionaryMember>? dictionary)
        {
            dictionary = null;
            List<DictionaryMember> members = [];
            HashSet<string> keys = new(StringComparer.Ordinal);

            while (!AtEnd)
            {
                if (!TryParseKey(out string? key))
                {
                    return false;
                }

                MemberValue? value;
                if (TryConsume('='))
                {
                    if (!TryParseItemOrInnerList(out value))
                    {
                        return false;
                    }
                }
                else
                {
                    if (!TryParseParameters(out List<Parameter>? parameters))
                    {
                        return false;
                    }

                    value = new Item(new BooleanItem(true), parameters);
                }

                if (!keys.Add(key))
                {
                    return false;
                }

                members.Add(new DictionaryMember(key, value));

                SkipOptionalWhitespace();
                if (AtEnd)
                {
                    break;
                }

                if (!TryConsume(','))
                {
                    return false;
                }

                SkipOptionalWhitespace();

                // A trailing comma.
                if (AtEnd)
                {
                    return false;
                }
            }

            dictionary = members;
            return true;
        }

        // RFC 8941 §4.2.1.1.
        private bool TryParseItemOrInnerList([NotNullWhen(true)] out MemberValue? value)
        {
            value = null;

            if (Next('('))
            {
                if (!TryParseInnerList(out InnerList? innerList))
                {
                    return false;
                }

                value = innerList;
                return true;
            }

            if (!TryParseItem(out Item? item))
            {
                return false;
            }

            value = item;
            return true;
        }

        // RFC 8941 §4.2.1.2.
        private bool TryParseInnerList([NotNullWhen(true)] out InnerList? innerList)
        {
            innerList = null;

            if (!TryConsume('('))
            {
                return false;
            }

            List<Item> items = [];

            while (!AtEnd)
            {
                SkipSpaces();

                if (TryConsume(')'))
                {
                    if (!TryParseParameters(out List<Parameter>? parameters))
                    {
                        return false;
                    }

                    innerList = new InnerList(items, parameters);
                    return true;
                }

                if (!TryParseItem(out Item? item))
                {
                    return false;
                }

                items.Add(item);

                if (!Next(' ') && !Next(')'))
                {
                    return false;
                }
            }

            // The end of the inner list was not found.
            return false;
        }

        // RFC 8941 §4.2.3.
        private bool TryParseItem([NotNullWhen(true)] out Item? item)
        {
            item = null;

            if (!TryParseBareItem(out BareItem? value) || !TryParseParameters(out List<Parameter>? parameters))
            {
                return false;
            }

            item = new Item(value, parameters);
            return true;
        }

        // RFC 8941 §4.2.3.1.
        private bool TryParseBareItem([NotNullWhen(true)] out BareItem? value)
        {
            value = null;

            if (AtEnd)
            {
                return false;
            }

            char first = input[_position];

            if (first == '-' || char.IsAsciiDigit(first))
            {
                return TryParseIntegerOrDecimal(out value);
            }

            if (first == '"')
            {
                return TryParseString(out value);
            }

            if (char.IsAsciiLetter(first) || first == '*')
            {
                return TryParseToken(out value);
            }

            if (first == ':')
            {
                return TryParseByteSequence(out value);
            }

            if (first == '?')
            {
                return TryParseBoolean(out value);
            }

            return false;
        }

        // RFC 8941 §4.2.3.2.
        private bool TryParseParameters([NotNullWhen(true)] out List<Parameter>? parameters)
        {
            parameters = null;
            List<Parameter> result = [];
            HashSet<string> keys = new(StringComparer.Ordinal);

            while (TryConsume(';'))
            {
                SkipSpaces();

                if (!TryParseKey(out string? key))
                {
                    return false;
                }

                BareItem value = new BooleanItem(true);
                if (TryConsume('='))
                {
                    if (!TryParseBareItem(out BareItem? parsed))
                    {
                        return false;
                    }

                    value = parsed;
                }

                if (!keys.Add(key))
                {
                    return false;
                }

                result.Add(new Parameter(key, value));
            }

            parameters = result;
            return true;
        }

        // RFC 8941 §4.2.3.3.
        private bool TryParseKey([NotNullWhen(true)] out string? key)
        {
            key = null;

            if (AtEnd || !(char.IsAsciiLetterLower(input[_position]) || input[_position] == '*'))
            {
                return false;
            }

            int start = _position;
            while (!AtEnd && IsKeyCharacter(input[_position]))
            {
                _position++;
            }

            key = input[start.._position];
            return true;
        }

        // RFC 8941 §4.2.4.
        private bool TryParseIntegerOrDecimal([NotNullWhen(true)] out BareItem? value)
        {
            value = null;

            bool negative = TryConsume('-');
            if (AtEnd || !char.IsAsciiDigit(input[_position]))
            {
                return false;
            }

            int start = _position;
            bool isDecimal = false;

            while (!AtEnd)
            {
                char c = input[_position];

                if (char.IsAsciiDigit(c))
                {
                    _position++;
                }
                else if (!isDecimal && c == '.')
                {
                    // At most 12 digits before the decimal point.
                    if (_position - start > 12)
                    {
                        return false;
                    }

                    isDecimal = true;
                    _position++;
                }
                else
                {
                    break;
                }

                // At most 15 digits in an integer, and 16 characters in a decimal including its point.
                if (_position - start > (isDecimal ? 16 : 15))
                {
                    return false;
                }
            }

            ReadOnlySpan<char> number = input.AsSpan(start, _position - start);

            if (!isDecimal)
            {
                long integer = long.Parse(number, NumberStyles.None, CultureInfo.InvariantCulture);
                value = new IntegerItem(negative ? -integer : integer);
                return true;
            }

            // One to three digits after the decimal point.
            int fractionLength = number.Length - number.IndexOf('.') - 1;
            if (fractionLength is 0 or > 3)
            {
                return false;
            }

            decimal parsed = decimal.Parse(number, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
            value = new DecimalItem(negative ? -parsed : parsed);
            return true;
        }

        // RFC 8941 §4.2.5.
        private bool TryParseString([NotNullWhen(true)] out BareItem? value)
        {
            value = null;

            if (!TryConsume('"'))
            {
                return false;
            }

            StringBuilder builder = new();

            while (!AtEnd)
            {
                char c = input[_position++];

                if (c == '\\')
                {
                    if (AtEnd)
                    {
                        return false;
                    }

                    char escaped = input[_position++];
                    if (escaped is not ('"' or '\\'))
                    {
                        return false;
                    }

                    builder.Append(escaped);
                }
                else if (c == '"')
                {
                    value = new StringItem(builder.ToString());
                    return true;
                }
                else if (c is < ' ' or > '~')
                {
                    return false;
                }
                else
                {
                    builder.Append(c);
                }
            }

            // The closing quote was not found.
            return false;
        }

        // RFC 8941 §4.2.6.
        private bool TryParseToken([NotNullWhen(true)] out BareItem? value)
        {
            value = null;

            if (AtEnd || !(char.IsAsciiLetter(input[_position]) || input[_position] == '*'))
            {
                return false;
            }

            int start = _position;
            while (!AtEnd && (IsTokenCharacter(input[_position]) || input[_position] is ':' or '/'))
            {
                _position++;
            }

            value = new TokenItem(input[start.._position]);
            return true;
        }

        // RFC 8941 §4.2.7.
        private bool TryParseByteSequence([NotNullWhen(true)] out BareItem? value)
        {
            value = null;

            if (!TryConsume(':'))
            {
                return false;
            }

            int end = input.IndexOf(':', _position);
            if (end < 0)
            {
                return false;
            }

            string content = input[_position..end];
            _position = end + 1;

            if (!content.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))
            {
                return false;
            }

            value = new ByteSequenceItem(content);
            return true;
        }

        // RFC 8941 §4.2.8.
        private bool TryParseBoolean([NotNullWhen(true)] out BareItem? value)
        {
            value = null;

            if (!TryConsume('?'))
            {
                return false;
            }

            if (TryConsume('1'))
            {
                value = new BooleanItem(true);
                return true;
            }

            if (TryConsume('0'))
            {
                value = new BooleanItem(false);
                return true;
            }

            return false;
        }

        private void SkipOptionalWhitespace()
        {
            while (Next(' ') || Next('\t'))
            {
                _position++;
            }
        }

        private bool Next(char expected)
        {
            return !AtEnd && input[_position] == expected;
        }

        private bool TryConsume(char expected)
        {
            if (!Next(expected))
            {
                return false;
            }

            _position++;
            return true;
        }

        private static bool IsKeyCharacter(char c)
        {
            return char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '_' or '-' or '.' or '*';
        }
    }
}
