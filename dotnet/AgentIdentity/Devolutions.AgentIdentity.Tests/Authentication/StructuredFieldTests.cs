using System.Globalization;

using static Devolutions.AgentIdentity.StructuredField;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The RFC 8941 parser and serializer behind the signature fields.
/// </summary>
/// <remarks>
/// The signature profile rejects most of these forms whatever they parse to,
/// so a request cannot show that the parser reads them as RFC 8941 does.
/// </remarks>
public class StructuredFieldTests
{
    // Each expected value names the RFC 8941 type of each value,
    // so a value of another type, or a success without a value, fails.
    [Theory]
    // Step 2: leading spaces are discarded.
    // oracle: spec RFC 8941 §4.2
    [InlineData(" sig=1", "sig=Integer(1)")]
    // A comma with optional white space around it separates members.
    // oracle: spec RFC 8941 §4.2.2
    [InlineData("sig=1, other=2", "sig=Integer(1), other=Integer(2)")]
    // oracle: spec RFC 8941 §4.2.2
    [InlineData("sig=1 , other=2", "sig=Integer(1), other=Integer(2)")]
    // oracle: spec RFC 8941 §4.2.2
    [InlineData("sig=1\t,\tother=2", "sig=Integer(1), other=Integer(2)")]
    // RFC 8941 §4.2.2 and §4.2.3.2: a member or a parameter without a value is the Boolean true.
    // oracle: spec RFC 8941 §4.2.2
    [InlineData("sig", "sig=Boolean(True)")]
    // oracle: spec RFC 8941 §4.2.3.2
    [InlineData("sig=1;x", "sig=Integer(1);x=Boolean(True)")]
    // A key may start with an asterisk.
    // oracle: spec RFC 8941 §4.2.3.3
    [InlineData("*=1", "*=Integer(1)")]
    // A decimal has at most 12 integer digits and one to three fraction digits.
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=1.23", "sig=Decimal(1.23)")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=-1.23", "sig=Decimal(-1.23)")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=1.234", "sig=Decimal(1.234)")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("abcdef=1.0", "abcdef=Decimal(1.0)")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=123456789012.123", "sig=Decimal(123456789012.123)")]
    // A string holds printable ASCII, and a backslash escapes a quote or a backslash.
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x y\"", "sig=String(x y)")]
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x~y\"", "sig=String(x~y)")]
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x\\\"y\"", "sig=String(x\"y)")]
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x\\\\y\"", "sig=String(x\\y)")]
    // A token starts with a letter or an asterisk, and may hold a colon or a slash.
    // oracle: spec RFC 8941 §4.2.6
    [InlineData("sig=abc", "sig=Token(abc)")]
    // oracle: spec RFC 8941 §4.2.6
    [InlineData("sig=*abc", "sig=Token(*abc)")]
    // oracle: spec RFC 8941 §4.2.6
    [InlineData("sig=ab:/c", "sig=Token(ab:/c)")]
    // oracle: spec RFC 8941 §4.2.8
    [InlineData("sig=?1", "sig=Boolean(True)")]
    // oracle: spec RFC 8941 §4.2.8
    [InlineData("sig=?0", "sig=Boolean(False)")]
    public void ParsesADictionary(string input, string expected)
    {
        Assert.True(TryParseDictionary(input, out IReadOnlyList<DictionaryMember>? dictionary));
        Assert.Equal(expected, Describe(dictionary));
    }

    [Theory]
    // Step 1: a field value is ASCII.
    // oracle: spec RFC 8941 §4.2
    [InlineData("sig\u0080=1")]
    // A key starts with a lowercase letter or an asterisk.
    // oracle: spec RFC 8941 §4.2.3.3
    [InlineData("Sig=1")]
    // An item starts with the first character of a bare item.
    // oracle: spec RFC 8941 §4.2.3.1
    [InlineData("sig=")]
    // oracle: spec RFC 8941 §4.2.3.1
    [InlineData("sig=@")]
    // oracle: spec RFC 8941 §4.2.3.1
    [InlineData("sig=,x=1")]
    // A parameter has a key.
    // oracle: spec RFC 8941 §4.2.3.2
    [InlineData("sig;")]
    // oracle: spec RFC 8941 §4.2.3.2
    [InlineData("sig=1;")]
    // oracle: spec RFC 8941 §4.2.3.2
    [InlineData("sig=(\"@method\");")]
    // CONTRACT.agent-identity.md §6 step 1 rejects a repeated key, of which RFC 8941 §4.2.2 would keep the last.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-signatures
    [InlineData("sig=1, sig=2")]
    // A comma separates members, and none follows the last.
    // oracle: spec RFC 8941 §4.2.2
    [InlineData("sig=1 x")]
    // oracle: spec RFC 8941 §4.2.2
    [InlineData("sig=1,")]
    // An inner list ends with a closing parenthesis.
    // oracle: spec RFC 8941 §4.2.1.2
    [InlineData("sig=(")]
    // oracle: spec RFC 8941 §4.2.1.2
    [InlineData("sig=( ")]
    // oracle: spec RFC 8941 §4.2.1.2
    [InlineData("sig=(\"@method\"")]
    // A digit follows the sign, an integer has at most 15 digits, and a decimal has one to three fraction digits.
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=-")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=1234567890123456")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=1.2345")]
    // oracle: spec RFC 8941 §4.2.4
    [InlineData("sig=1.")]
    // A backslash escapes a quote or a backslash, DEL is not printable, and a quote ends a string.
    // Each string reaches the end of the input, so the parser cannot fail later on a character after it.
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x\\")]
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x\\q")]
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x\u007F")]
    // oracle: spec RFC 8941 §4.2.5
    [InlineData("sig=\"x")]
    // A byte sequence ends with a colon and holds only base64 characters.
    // oracle: spec RFC 8941 §4.2.7
    [InlineData("sig=:")]
    // oracle: spec RFC 8941 §4.2.7
    [InlineData("sig=:A!==:")]
    // A Boolean is ?1 or ?0.
    // oracle: spec RFC 8941 §4.2.8
    [InlineData("sig=?")]
    public void RejectsAMalformedDictionary(string input)
    {
        Assert.False(TryParseDictionary(input, out _));
    }

    // A string is quoted, and a backslash precedes each quote or backslash in it.
    // oracle: spec RFC 8941 §4.1.6
    [Theory]
    [InlineData("", "\"\"")]
    [InlineData("x", "\"x\"")]
    [InlineData("\"", "\"\\\"\"")]
    [InlineData("\\", "\"\\\\\"")]
    public void SerializesAString(string value, string expected)
    {
        Assert.Equal(expected, SerializeString(value));
    }

    // Each member as its key, its item and its parameters, such as sig=Integer(1);x=Boolean(True).
    private static string Describe(IReadOnlyList<DictionaryMember> dictionary)
    {
        return string.Join(", ", dictionary.Select(member => $"{member.Key}={Describe((Item)member.Value)}"));
    }

    private static string Describe(Item item)
    {
        return Describe(item.Value)
            + string.Concat(item.Parameters.Select(parameter => $";{parameter.Key}={Describe(parameter.Value)}"));
    }

    private static string Describe(BareItem value)
    {
        return value switch
        {
            IntegerItem integer => $"Integer({integer.Value.ToString(CultureInfo.InvariantCulture)})",
            DecimalItem number => $"Decimal({number.Value.ToString("0.0##", CultureInfo.InvariantCulture)})",
            StringItem text => $"String({text.Value})",
            TokenItem token => $"Token({token.Value})",
            ByteSequenceItem bytes => $"ByteSequence({bytes.Base64})",
            BooleanItem boolean => $"Boolean({boolean.Value})",
            _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Not a bare item."),
        };
    }
}
