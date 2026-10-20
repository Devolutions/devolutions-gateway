using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// What a test reads from the result of parsing any of the request bodies.
/// </summary>
public sealed record RequestBodyOutcome(
    bool Succeeded,
    AgentIdentityError? Error,
    string? FailureDetail,
    AgentMetadata? Metadata,
    CertificateSigningRequest? Csr);

/// <summary>
/// The rules that every request body shares (CONTRACT.md §1 and §3); each derived class runs them on one body type.
/// </summary>
public abstract class RequestBodyTests
{
    protected const string ValidMetadata = """{"hostname": "host"}""";

    /// <summary>
    /// A valid body of the type under test, with the given metadata member, omitted when null,
    /// and the given members after the others.
    /// </summary>
    protected abstract string Body(string? metadata, string extraMembers);

    protected abstract RequestBodyOutcome Parse(byte[] utf8Json);

    [Fact]
    public void AcceptsValidBody()
    {
        AgentMetadata metadata = AssertValid(ParseText(Body(ValidMetadata, ""))).Metadata!;

        Assert.Equal([new KeyValuePair<string, string>("hostname", "host")], metadata);
    }

    // CONTRACT.md §1: receivers ignore unknown JSON fields.
    // A name repeated in different objects is not a repeated member.
    [Theory]
    [InlineData(""" "extra": 1""")]
    [InlineData(""" "extra": {"nested": [1, 2.5e3, true, false, null, {"a": "b"}]}""")]
    [InlineData(""" "version": 2, "extra": "h\u00e9 \ud83d\ude00" """)]
    [InlineData(""" "extra": null""")]
    [InlineData(""" "a": {"b": 1}, "c": {"b": 1}""")]
    [InlineData(""" "extra": [{"b": 1}, {"b": 1}]""")]
    public void AcceptsUnknownMembers(string extraMembers)
    {
        AssertValid(ParseText(Body(ValidMetadata, extraMembers)));
    }

    [Fact]
    public void ReturnsTheMetadataUnescapedInTheOrderSent()
    {
        RequestBodyOutcome outcome = ParseText(Body("""{"os_name": "Windows", "host\u006eame": "h\u00e9"}""", ""));
        KeyValuePair<string, string>[] expected = [new("os_name", "Windows"), new("hostname", "hé")];

        Assert.Equal(expected, AssertValid(outcome).Metadata!);
    }

    // CONTRACT.md §3: metadata may be an empty object.
    [Fact]
    public void AcceptsEmptyMetadata()
    {
        Assert.Empty(AssertValid(ParseText(Body("{}", ""))).Metadata!);
    }

    // CONTRACT.md §3: metadata is required, and §1 reads a null member as an absent one.
    [Theory]
    [InlineData(null)]
    [InlineData("null")]
    public void RejectsMissingMetadata(string? metadata)
    {
        AssertInvalid(ParseText(Body(metadata, "")));
    }

    // CONTRACT.md §3: metadata is a JSON object of string to string.
    [Theory]
    [InlineData(""" "host" """)]
    [InlineData("[]")]
    [InlineData("""[{"hostname": "host"}]""")]
    [InlineData("1")]
    [InlineData("true")]
    public void RejectsMetadataThatIsNotAnObject(string metadata)
    {
        AssertInvalid(ParseText(Body(metadata, "")));
    }

    [Theory]
    [InlineData("""{"hostname": 1}""")]
    [InlineData("""{"hostname": true}""")]
    [InlineData("""{"hostname": null}""")]
    [InlineData("""{"hostname": {}}""")]
    [InlineData("""{"hostname": ["host"]}""")]
    [InlineData("""{"hostname": {"name": "host"}}""")]
    public void RejectsMetadataValueThatIsNotAString(string metadata)
    {
        AssertInvalid(ParseText(Body(metadata, "")));
    }

    // The limits of CONTRACT.md §3 apply to metadata in a body as they do anywhere else.
    public static TheoryData<string, string> MetadataBeyondTheLimits => new()
    {
        { "33 keys", JsonObject([.. Enumerable.Range(0, 33).Select(i => $"\"key_{i}\": \"value\"")]) },
        { "uppercase letter in a key", """{"Hostname": "host"}""" },
        { "key ending in a line feed", """{"hostname\n": "host"}""" },
        { "C0 control character in a value", """{"hostname": "a\u0007b"}""" },
        { "C1 control character in a value", """{"hostname": "a\u0085b"}""" },
        { "value of 1025 UTF-8 bytes", $$"""{"hostname": "{{string.Concat(Enumerable.Repeat("\u00E9", 512))}}a"}""" },
    };

    [Theory]
    [MemberData(nameof(MetadataBeyondTheLimits))]
    public void RejectsMetadataBeyondTheLimits(string form, string metadata)
    {
        AssertInvalid(ParseText(Body(metadata, "")), form);
    }

    // CONTRACT.md §1: a body that repeats a member name at any depth, such as one metadata key twice, is invalid,
    // whether the names are written alike or only unescape alike.
    [Theory]
    [InlineData("metadata", ValidMetadata, """ "metadata": {}""")]
    [InlineData("metadata with an escaped letter", ValidMetadata, """ "m\u0065tadata": {}""")]
    [InlineData("metadata key", """{"hostname": "a", "hostname": "a"}""", "")]
    [InlineData("unknown member", ValidMetadata, """ "extra": 1, "extra": 2""")]
    [InlineData("member of an unknown member", ValidMetadata, """ "extra": {"a": 1, "a": 2}""")]
    [InlineData("member of an object in nested arrays", ValidMetadata, """ "extra": [[{"x": {"a": null, "a": null}}]]""")]
    public void RejectsRepeatedMemberName(string form, string metadata, string extraMembers)
    {
        AssertInvalid(ParseText(Body(metadata, extraMembers)), form);
    }

    // RFC 8259 §2: a JSON text is one value; RFC 8259 §8.1 lets a parser reject a byte order mark.
    [Theory]
    [InlineData("trailing content", "", "x")]
    [InlineData("second value", "", " {}")]
    [InlineData("line comment after the object", "", " // comment")]
    [InlineData("block comment before the object", "/* comment */", "")]
    [InlineData("byte order mark", "\uFEFF", "")]
    [InlineData("object inside an array", "[", "]")]
    public void RejectsTextAroundTheObject(string form, string prefix, string suffix)
    {
        AssertInvalid(ParseText(prefix + Body(ValidMetadata, "") + suffix), form);
    }

    // RFC 8259 grammar, which has no comments, trailing commas, single quotes or NaN.
    [Theory]
    [InlineData("trailing comma in the object", """ "extra": 1,""")]
    [InlineData("trailing comma in an array", """ "extra": [1,]""")]
    [InlineData("comment", """ /* comment */ "extra": 1""")]
    [InlineData("single-quoted name", """ 'extra': 1""")]
    [InlineData("unquoted name", """ extra: 1""")]
    [InlineData("NaN", """ "extra": NaN""")]
    [InlineData("number with a leading zero", """ "extra": 01""")]
    [InlineData("unescaped tab in a string", " \"extra\": \"a\tb\"")]
    [InlineData("missing value", """ "extra":""")]
    [InlineData("missing colon", """ "extra" 1""")]
    public void RejectsMalformedMember(string form, string extraMembers)
    {
        AssertInvalid(ParseText(Body(ValidMetadata, extraMembers)), form);
    }

    [Fact]
    public void RejectsTruncatedBody()
    {
        AssertInvalid(ParseText(Body(ValidMetadata, "")[..^1]));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData(""" "body" """)]
    [InlineData("42")]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("")]
    [InlineData(" ")]
    public void RejectsBodyThatIsNotAnObject(string json)
    {
        AssertInvalid(ParseText(json));
    }

    // RFC 8259 §8.2: an escaped unpaired surrogate is valid JSON syntax but no Unicode text,
    // so parsers disagree on what it reads as.
    [Theory]
    [InlineData("lone high surrogate", """ "extra": "\ud800" """)]
    [InlineData("lone low surrogate", """ "extra": "\udc00" """)]
    [InlineData("high surrogate before another character", """ "extra": "\ud800\u0041" """)]
    [InlineData("lone surrogate in a name", """ "\ud800": 1""")]
    public void RejectsEscapedStringThatIsNotUnicode(string form, string extraMembers)
    {
        AssertInvalid(ParseText(Body(ValidMetadata, extraMembers)), form);
    }

    // CONTRACT.md §1 and RFC 8259 §8.1: JSON bodies are UTF-8.
    // The bytes replace the character of a string in an unknown member.
    [Theory]
    [InlineData(new byte[] { 0xFF })]
    [InlineData(new byte[] { 0xC0, 0xAF })]
    [InlineData(new byte[] { 0xED, 0xA0, 0x80 })]
    [InlineData(new byte[] { 0xF4, 0x90, 0x80, 0x80 })]
    public void RejectsStringThatIsNotUtf8(byte[] bytes)
    {
        byte[] body = Encoding.UTF8.GetBytes(Body(ValidMetadata, """ "extra": "#" """));
        int index = Array.IndexOf(body, (byte)'#');

        AssertInvalid(Parse([.. body[..index], .. bytes, .. body[(index + 1)..]]));
    }

    // The body object is the first level, so 63 nested arrays reach 64 levels.
    [Fact]
    public void AcceptsNestingOf64Levels()
    {
        AssertValid(ParseText(Body(ValidMetadata, NestedArrays(63))));
    }

    [Fact]
    public void RejectsNestingOf65Levels()
    {
        AssertInvalid(ParseText(Body(ValidMetadata, NestedArrays(64))));
    }

    protected static string JsonObject(params string?[] members)
    {
        return "{" + string.Join(", ", members.Where(member => !string.IsNullOrEmpty(member))) + "}";
    }

    protected static string? MetadataMember(string? metadata)
    {
        return metadata is null ? null : $"\"metadata\": {metadata}";
    }

    protected RequestBodyOutcome ParseText(string json)
    {
        return Parse(Encoding.UTF8.GetBytes(json));
    }

    protected static RequestBodyOutcome AssertValid(RequestBodyOutcome outcome)
    {
        Assert.True(outcome.Succeeded, outcome.FailureDetail);
        Assert.Null(outcome.Error);
        Assert.Null(outcome.FailureDetail);
        Assert.NotNull(outcome.Metadata);

        return outcome;
    }

    // The body parsers report every failure as invalid_request with HTTP status 400.
    protected static void AssertInvalid(RequestBodyOutcome outcome, string? form = null)
    {
        Assert.False(outcome.Succeeded, form);
        Assert.NotNull(outcome.Error);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, outcome.Error.Code);
        Assert.Equal(400, outcome.Error.HttpStatusCode);
        Assert.Equal(AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest).Message, outcome.Error.Message);
        Assert.False(string.IsNullOrEmpty(outcome.FailureDetail));
        Assert.Null(outcome.Metadata);
        Assert.Null(outcome.Csr);
    }

    private static string NestedArrays(int depth)
    {
        return $"\"extra\": {new string('[', depth)}{new string(']', depth)}";
    }
}

/// <summary>
/// The rules of a body that carries a CSR (CONTRACT.md §1, §4, §5.2 and §5.3).
/// </summary>
public abstract class CsrRequestBodyTests : RequestBodyTests
{
    protected static readonly string ValidCsr = Convert.ToBase64String(TestVectors.Instance.Csr["valid"].Csr);

    protected sealed override string Body(string? metadata, string extraMembers)
    {
        return BodyWithCsr(Quote(ValidCsr), metadata, extraMembers);
    }

    [Fact]
    public void ReturnsTheValidatedCsr()
    {
        CsrVector vector = TestVectors.Instance.Csr["valid"];
        Assert.NotNull(vector.PublicKeySec1);
        byte[] expected = [.. CertificateSigningRequestTests.P256SubjectPublicKeyInfoPrefix, .. vector.PublicKeySec1];

        CertificateSigningRequest csr = AssertValid(ParseText(Body(ValidMetadata, ""))).Csr!;

        Assert.Equal(expected, csr.SubjectPublicKeyInfo.ToArray());
        Assert.Equal(SHA256.HashData(expected), csr.SubjectPublicKeyInfoSha256.ToArray());
    }

    // CONTRACT.md §5.2 and §5.3: csr is required, and §1 reads a null member as an absent one.
    [Theory]
    [InlineData(null)]
    [InlineData("null")]
    public void RejectsMissingCsr(string? csr)
    {
        AssertInvalid(ParseText(BodyWithCsr(csr, ValidMetadata)));
    }

    // CONTRACT.md §1: a CSR is DER encoded base64 in a JSON string.
    [Theory]
    [InlineData("1")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("true")]
    public void RejectsCsrThatIsNotAString(string csr)
    {
        AssertInvalid(ParseText(BodyWithCsr(csr, ValidMetadata)));
    }

    // CONTRACT.md §1: base64 in any form but the canonical one is invalid.
    // Each test alters the canonical base64 of a request that the body accepts,
    // into a form that a lenient decoder would still read as that request.
    // The requests are built here rather than read from the vector file,
    // so that each form applies to them whatever request the file holds.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void RejectsCsrWithoutPadding(int octetsInFinalQuantum)
    {
        string canonical = CanonicalCsr(octetsInFinalQuantum);

        AssertOnlyCanonicalCsrIsValid(canonical, canonical.TrimEnd('='));
    }

    // RFC 4648 §3.5: the pad bits of the final quantum, four after one octet and two after two octets, are zero.
    // The character before the padding holds them, so setting its lowest bit sets one pad bit.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void RejectsCsrWithNonZeroPadBit(int octetsInFinalQuantum)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        string canonical = CanonicalCsr(octetsInFinalQuantum);
        int last = canonical.TrimEnd('=').Length - 1;
        char withPadBit = Alphabet[Alphabet.IndexOf(canonical[last]) | 1];

        AssertOnlyCanonicalCsrIsValid(canonical, canonical[..last] + withPadBit + canonical[(last + 1)..]);
    }

    // A lenient decoder skips white space, such as the line breaks that RFC 7468 places every 64 characters.
    [Theory]
    [InlineData("\n")]
    [InlineData(" ")]
    public void RejectsCsrWithWhiteSpace(string whiteSpace)
    {
        string canonical = CanonicalCsr(1);

        AssertOnlyCanonicalCsrIsValid(canonical, canonical[..64] + whiteSpace + canonical[64..]);
    }

    // RFC 4648 §5: the base64url alphabet writes - and _ for the + and / of base64.
    [Fact]
    public void RejectsCsrInTheBase64UrlAlphabet()
    {
        string canonical = CanonicalCsr(1);

        AssertOnlyCanonicalCsrIsValid(canonical, canonical.Replace('+', '-').Replace('/', '_'));
    }

    [Fact]
    public void RejectsCsrThatFailsValidation()
    {
        string csr = Convert.ToBase64String(TestVectors.Instance.Csr["bad_self_signature"].Csr);

        AssertInvalid(ParseText(BodyWithCsr(Quote(csr), ValidMetadata)));
    }

    [Fact]
    public void RejectsEmptyCsr()
    {
        AssertInvalid(ParseText(BodyWithCsr(Quote(""), ValidMetadata)));
    }

    [Fact]
    public void RejectsRepeatedCsr()
    {
        AssertInvalid(ParseText(Body(ValidMetadata, $"\"csr\": {Quote(ValidCsr)}")));
    }

    private static string BodyWithCsr(string? csr, string? metadata, string extraMembers = "")
    {
        return JsonObject(csr is null ? null : $"\"csr\": {csr}", MetadataMember(metadata), extraMembers);
    }

    // The canonical base64 of a request whose DER length leaves the given number of octets in the final quantum,
    // and whose encoding uses both + and /.
    // Each attempt signs another subject, so that the search does not rely on random signatures.
    private static string CanonicalCsr(int octetsInFinalQuantum)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        for (int attempt = 0; attempt < 64; attempt++)
        {
            byte[] subject = new X500DistinguishedName($"CN=attempt {attempt}").RawData;
            byte[] der = TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject), key);
            string base64 = Convert.ToBase64String(der);

            if (der.Length % 3 == octetsInFinalQuantum && base64.Contains('+') && base64.Contains('/'))
            {
                return base64;
            }
        }

        throw new InvalidOperationException("No request met the conditions in 64 attempts.");
    }

    private void AssertOnlyCanonicalCsrIsValid(string canonical, string altered)
    {
        Assert.NotEqual(canonical, altered);
        AssertValid(ParseText(BodyWithCsr(Quote(canonical), ValidMetadata)));

        AssertInvalid(ParseText(BodyWithCsr(Quote(altered), ValidMetadata)));
    }

    // The base64 alphabet needs no escape in a JSON string; a line break does.
    private static string Quote(string text)
    {
        return $"\"{text.Replace("\n", "\\n")}\"";
    }
}

public class EnrollRequestBodyTests : CsrRequestBodyTests
{
    protected override RequestBodyOutcome Parse(byte[] utf8Json)
    {
        RequestBodyParseResult<EnrollRequestBody> result = EnrollRequestBody.Parse(utf8Json);

        return new RequestBodyOutcome(
            result.Succeeded,
            result.Error,
            result.FailureDetail,
            result.Body?.Metadata,
            result.Body?.Csr);
    }
}

public class RenewRequestBodyTests : CsrRequestBodyTests
{
    protected override RequestBodyOutcome Parse(byte[] utf8Json)
    {
        RequestBodyParseResult<RenewRequestBody> result = RenewRequestBody.Parse(utf8Json);

        return new RequestBodyOutcome(
            result.Succeeded,
            result.Error,
            result.FailureDetail,
            result.Body?.Metadata,
            result.Body?.Csr);
    }
}

public class CheckInRequestBodyTests : RequestBodyTests
{
    // CONTRACT.md §5.6: a check-in body has no csr, so a csr member is an unknown member.
    [Fact]
    public void IgnoresCsrMember()
    {
        AssertValid(ParseText(Body(ValidMetadata, """ "csr": 42""")));
    }

    protected override string Body(string? metadata, string extraMembers)
    {
        return JsonObject(MetadataMember(metadata), extraMembers);
    }

    protected override RequestBodyOutcome Parse(byte[] utf8Json)
    {
        RequestBodyParseResult<CheckInRequestBody> result = CheckInRequestBody.Parse(utf8Json);

        return new RequestBodyOutcome(
            result.Succeeded,
            result.Error,
            result.FailureDetail,
            result.Body?.Metadata,
            Csr: null);
    }
}
