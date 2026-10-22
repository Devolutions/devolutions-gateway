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
/// The rules that every request body shares (CONTRACT.agent-identity.md §1 and §3);
/// each derived class runs them on one body type.
/// </summary>
public abstract class RequestBodyTests
{
    protected const string ValidMetadata = """{"hostname": "host"}""";

    // Text that the metadata entry where a body fails holds in its key and in its value.
    private const string LeakedKey = "leaked_key";
    private const string LeakedValue = "leaked value";

    /// <summary>
    /// A valid body of the type under test, with the given metadata member, omitted when null,
    /// and the given members after the others.
    /// </summary>
    protected abstract string Body(string? metadata, string extraMembers);

    protected abstract RequestBodyOutcome Parse(byte[] utf8Json);

    // CONTRACT.agent-identity.md §5.2, §5.3 and §5.6 define the bodies, and §3 their metadata.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    [Fact]
    public void AcceptsValidBody()
    {
        AgentMetadata metadata = AssertValid(ParseText(Body(ValidMetadata, ""))).Metadata!;

        Assert.Equal([new KeyValuePair<string, string>("hostname", "host")], metadata);
    }

    // Receivers ignore unknown JSON fields.
    // A name repeated in different objects is not a repeated member.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData(""" "extra": 1""")]
    [InlineData(""" "extra": {"nested": [1, 2.5e3, true, false, null, {"a": "b"}]}""")]
    [InlineData(""" "version": 2, "extra": "h\u00e9 \ud83d\ude00" """)]
    [InlineData(""" "extra": null""")]
    // oracle: spec RFC 8259 §4
    [InlineData(""" "a": {"b": 1}, "c": {"b": 1}""")]
    // oracle: spec RFC 8259 §4
    [InlineData(""" "extra": [{"b": 1}, {"b": 1}]""")]
    public void AcceptsUnknownMembers(string extraMembers)
    {
        AssertValid(ParseText(Body(ValidMetadata, extraMembers)));
    }

    // An escape stands for its character.
    // oracle: spec RFC 8259 §7
    [Fact]
    public void ReturnsTheMetadataUnescaped()
    {
        RequestBodyOutcome outcome = ParseText(Body("""{"os_name": "Windows", "host\u006eame": "h\u00e9"}""", ""));
        KeyValuePair<string, string>[] expected = [new("hostname", "hé"), new("os_name", "Windows")];

        Assert.Equal(expected, AssertValid(outcome).Metadata!.OrderBy(entry => entry.Key, StringComparer.Ordinal));
    }

    // Metadata may be an empty object.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Fact]
    public void AcceptsEmptyMetadata()
    {
        Assert.Empty(AssertValid(ParseText(Body("{}", ""))).Metadata!);
    }

    // CONTRACT.agent-identity.md §3: metadata is required, and §1 reads a null member as an absent one.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [InlineData(null)]
    [InlineData("null")]
    public void RejectsMissingMetadata(string? metadata)
    {
        AssertInvalid(ParseText(Body(metadata, "")));
    }

    // Metadata is a JSON object of string to string.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
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

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
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

    // The limits of CONTRACT.agent-identity.md §3 apply to metadata in a body as they do anywhere else.
    public static TheoryData<string, string> MetadataBeyondTheLimits => new()
    {
        { "33 keys", JsonObject([.. Enumerable.Range(0, 33).Select(i => $"\"key_{i}\": \"value\"")]) },
        { "uppercase letter in a key", """{"Hostname": "host"}""" },
        { "key ending in a line feed", """{"hostname\n": "host"}""" },
        { "C0 control character in a value", """{"hostname": "a\u0007b"}""" },
        { "C1 control character in a value", """{"hostname": "a\u0085b"}""" },
        { "value of 1025 UTF-8 bytes", $$"""{"hostname": "{{string.Concat(Enumerable.Repeat("\u00E9", 512))}}a"}""" },
    };

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
    [Theory]
    [MemberData(nameof(MetadataBeyondTheLimits))]
    public void RejectsMetadataBeyondTheLimits(string form, string metadata)
    {
        AssertInvalid(ParseText(Body(metadata, "")), form);
    }

    // Metadata that fails at an entry whose key holds LeakedKey and whose value holds LeakedValue, by name.
    public static TheoryData<string, string> MetadataFailingAtAnEntry => new()
    {
        { "key outside the pattern", $$"""{"{{LeakedKey}}\n": "{{LeakedValue}}"}""" },
        { "repeated key", $$"""{"{{LeakedKey}}": "first", "{{LeakedKey}}": "{{LeakedValue}}"}""" },
        { "value with a control character", $$"""{"{{LeakedKey}}": "{{LeakedValue}}\u0007"}""" },
        { "value that is not Unicode", $$"""{"{{LeakedKey}}": "{{LeakedValue}}\ud800"}""" },
        {
            "value of 1025 UTF-8 bytes",
            $$"""{"{{LeakedKey}}": "{{LeakedValue + new string('a', 1025 - LeakedValue.Length)}}"}"""
        },
        { "value that is not a string", $$"""{"{{LeakedKey}}": ["{{LeakedValue}}"]}""" },
    };

    // The failure detail goes to host logs, so it holds no key or value of the metadata, valid or not,
    // since an agent could otherwise write into the authority's logs.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Failure details
    [Theory]
    [MemberData(nameof(MetadataFailingAtAnEntry))]
    public void FailureDetailHoldsNoMetadataKeyOrValue(string form, string metadata)
    {
        RequestBodyOutcome outcome = ParseText(Body(metadata, ""));

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        AssertInvalid(outcome, form);
        Assert.DoesNotContain(LeakedKey, outcome.FailureDetail);
        Assert.DoesNotContain(LeakedValue, outcome.FailureDetail);
    }

    // A body that repeats a member name at any depth, such as one metadata key twice,
    // is invalid, whether the names are written alike or only unescape alike.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData("metadata", ValidMetadata, """ "metadata": {}""")]
    // oracle: spec RFC 8259 §7
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
    // oracle: spec RFC 8259 §2
    [InlineData("trailing content", "", "x")]
    // oracle: spec RFC 8259 §2
    [InlineData("second value", "", " {}")]
    // oracle: spec RFC 8259 §2
    [InlineData("line comment after the object", "", " // comment")]
    // oracle: spec RFC 8259 §2
    [InlineData("block comment before the object", "/* comment */", "")]
    // oracle: spec RFC 8259 §2
    // oracle: spec RFC 8259 §8.1
    [InlineData("byte order mark", "\uFEFF", "")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    [InlineData("object inside an array", "[", "]")]
    public void RejectsTextAroundTheObject(string form, string prefix, string suffix)
    {
        AssertInvalid(ParseText(prefix + Body(ValidMetadata, "") + suffix), form);
    }

    // RFC 8259 grammar, which has no comments, trailing commas, single quotes or NaN.
    [Theory]
    // oracle: spec RFC 8259 §4
    [InlineData("trailing comma in the object", """ "extra": 1,""")]
    // oracle: spec RFC 8259 §5
    [InlineData("trailing comma in an array", """ "extra": [1,]""")]
    // oracle: spec RFC 8259 §2
    [InlineData("comment", """ /* comment */ "extra": 1""")]
    // oracle: spec RFC 8259 §7
    [InlineData("single-quoted name", """ 'extra': 1""")]
    // oracle: spec RFC 8259 §4
    [InlineData("unquoted name", """ extra: 1""")]
    // oracle: spec RFC 8259 §6
    [InlineData("NaN", """ "extra": NaN""")]
    // oracle: spec RFC 8259 §6
    [InlineData("number with a leading zero", """ "extra": 01""")]
    // oracle: spec RFC 8259 §7
    [InlineData("unescaped tab in a string", " \"extra\": \"a\tb\"")]
    // oracle: spec RFC 8259 §4
    [InlineData("missing value", """ "extra":""")]
    // oracle: spec RFC 8259 §4
    [InlineData("missing colon", """ "extra" 1""")]
    public void RejectsMalformedMember(string form, string extraMembers)
    {
        AssertInvalid(ParseText(Body(ValidMetadata, extraMembers)), form);
    }

    // oracle: spec RFC 8259 §4
    [Fact]
    public void RejectsTruncatedBody()
    {
        AssertInvalid(ParseText(Body(ValidMetadata, "")[..^1]));
    }

    // CONTRACT.agent-identity.md §5.2, §5.3 and §5.6: each body is a JSON object;
    // RFC 8259 §2: a JSON text holds one value.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
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

    // A string that is not valid Unicode, such as an escaped lone surrogate, in any member, including an unknown one,
    // is invalid, since parsers disagree on what it reads as.
    // A member name is a string too.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData("lone high surrogate", """ "extra": "\ud800" """)]
    [InlineData("lone low surrogate", """ "extra": "\udc00" """)]
    [InlineData("high surrogate before another character", """ "extra": "\ud800\u0041" """)]
    [InlineData("lone surrogate in a name", """ "\ud800": 1""")]
    public void RejectsEscapedStringThatIsNotUnicode(string form, string extraMembers)
    {
        AssertInvalid(ParseText(Body(ValidMetadata, extraMembers)), form);
    }

    // CONTRACT.agent-identity.md §1 and RFC 8259 §8.1: JSON bodies are UTF-8.
    // The bytes replace the character of a string in an unknown member.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: spec RFC 3629 §4
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

    // A body with more than 64 nested objects and arrays, counting the top-level object, is invalid.
    // The body object is the first, so 63 nested arrays make 64 and 64 make 65.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void AcceptsNestingOf64Levels()
    {
        AssertValid(ParseText(Body(ValidMetadata, NestedArrays(63))));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §metadata
        Assert.NotNull(outcome.Metadata);

        return outcome;
    }

    // The body parsers report every failure as invalid_request with HTTP status 400.
    protected static void AssertInvalid(RequestBodyOutcome outcome, string? form = null)
    {
        Assert.False(outcome.Succeeded, form);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        Assert.NotNull(outcome.Error);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, outcome.Error.Code);
        Assert.Equal(400, outcome.Error.HttpStatusCode);
        // oracle: mutant an empty failure detail for a missing or non-string csr, a CSR that is not DER PKCS #10
        // or fails its self-signature, missing or non-object metadata, a non-string metadata value,
        // more than 32 metadata keys, a key outside the pattern, or a value with a control character
        // or over 1024 UTF-8 bytes
        Assert.False(string.IsNullOrEmpty(outcome.FailureDetail));
    }

    private static string NestedArrays(int depth)
    {
        return $"\"extra\": {new string('[', depth)}{new string(']', depth)}";
    }
}

/// <summary>
/// The rules of a body that carries a CSR (CONTRACT.agent-identity.md §1, §4, §5.2 and §5.3).
/// </summary>
public abstract class CsrRequestBodyTests : RequestBodyTests
{
    protected static readonly string ValidCsr = Convert.ToBase64String(TestVectors.Instance.Csr["valid"].Csr);

    protected sealed override string Body(string? metadata, string extraMembers)
    {
        return BodyWithCsr(Quote(ValidCsr), metadata, extraMembers);
    }

    // test-vectors.json csr.valid gives the public key, which RFC 5480 §2 places in this SubjectPublicKeyInfo.
    // oracle: reference docs/agent-identity/test-vectors.json csr.valid
    // oracle: spec RFC 5480 §2
    [Fact]
    public void ReturnsTheValidatedCsr()
    {
        CsrVector vector = TestVectors.Instance.Csr["valid"];
        Assert.NotNull(vector.PublicKeySec1);
        byte[] expected = [.. CertificateSigningRequestTests.P256SubjectPublicKeyInfoPrefix, .. vector.PublicKeySec1];

        CertificateSigningRequest csr = AssertValid(ParseText(Body(ValidMetadata, ""))).Csr!;

        Assert.Equal(expected, csr.SubjectPublicKeyInfo.ToArray());
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
        Assert.Equal(SHA256.HashData(expected), csr.SubjectPublicKeyInfoSha256.ToArray());
    }

    // CONTRACT.agent-identity.md §5.2 and §5.3: csr is required, and §1 reads a null member as an absent one.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    [Theory]
    [InlineData(null)]
    [InlineData("null")]
    public void RejectsMissingCsr(string? csr)
    {
        AssertInvalid(ParseText(BodyWithCsr(csr, ValidMetadata)));
    }

    // A CSR is DER encoded base64 in a JSON string.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData("1")]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("true")]
    public void RejectsCsrThatIsNotAString(string csr)
    {
        AssertInvalid(ParseText(BodyWithCsr(csr, ValidMetadata)));
    }

    // Base64 in any form but the canonical one is invalid.
    // Each test alters the canonical base64 of a request that the body accepts,
    // into a form that a lenient decoder would still read as that request.
    // The requests are built here rather than read from the vector file,
    // so that each form applies to them whatever request the file holds.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §definitions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void RejectsCsrWithoutPadding(int octetsInFinalQuantum)
    {
        string canonical = CanonicalCsr(octetsInFinalQuantum);

        AssertOnlyCanonicalCsrIsValid(canonical, canonical.TrimEnd('='));
    }

    // The pad bits of the final quantum, four after one octet and two after two octets, are zero.
    // The character before the padding holds them, so setting its lowest bit sets one pad bit.
    // oracle: spec RFC 4648 §3.5
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: spec RFC 4648 §3.3
    [Theory]
    [InlineData("\n")]
    [InlineData(" ")]
    public void RejectsCsrWithWhiteSpace(string whiteSpace)
    {
        string canonical = CanonicalCsr(1);

        AssertOnlyCanonicalCsrIsValid(canonical, canonical[..64] + whiteSpace + canonical[64..]);
    }

    // RFC 4648 §5: the base64url alphabet writes - and _ for the + and / of base64.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §definitions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void RejectsCsrInTheBase64UrlAlphabet()
    {
        string canonical = CanonicalCsr(1);

        AssertOnlyCanonicalCsrIsValid(canonical, canonical.Replace('+', '-').Replace('/', '_'));
    }

    // test-vectors.json csr.bad_self_signature expects invalid_request.
    // oracle: reference docs/agent-identity/test-vectors.json csr.bad_self_signature
    [Fact]
    public void RejectsCsrThatFailsValidation()
    {
        string csr = Convert.ToBase64String(TestVectors.Instance.Csr["bad_self_signature"].Csr);

        AssertInvalid(ParseText(BodyWithCsr(Quote(csr), ValidMetadata)));
    }

    // A CSR is a DER SEQUENCE, which no empty byte string encodes.
    // oracle: spec RFC 2986 §4
    [Fact]
    public void RejectsEmptyCsr()
    {
        AssertInvalid(ParseText(BodyWithCsr(Quote(""), ValidMetadata)));
    }

    // CONTRACT.agent-identity.md §1 makes csr sent twice invalid_request.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
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
    // A check-in body has no csr, so a csr member is an unknown member.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
