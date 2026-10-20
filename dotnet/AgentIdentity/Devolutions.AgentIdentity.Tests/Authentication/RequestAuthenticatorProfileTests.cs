using System.Globalization;
using System.Security.Cryptography;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The parsing rules of CONTRACT.md §6 step 1, beyond the vectors.
/// </summary>
/// <remarks>
/// Each rejected request is signed over the base that a verifier without the rule under test would build,
/// so such a verifier would accept it, and only that rule can reject it.
/// </remarks>
public class RequestAuthenticatorProfileTests
{
    private const string OtherNonce = "EBESExQVFhcYGRobHB0eHw";

    // The 16 bytes "0123456789:;<=>?", whose base64url holds a '-'.
    private const string NonceWithDash = "MDEyMzQ1Njc4OTo7PD0-Pw";

    // The tag of a renew request, as Signature-Input writes it.
    private const string TagParameter = ";tag=\"renew\"";

    private static readonly DateTimeOffset Now = TestAuthority.DefaultNow;

    private static readonly Dictionary<string, Func<SignedHttpRequest>> StepOneViolations = new()
    {
        // RFC 8941 keeps the last of repeated keys; a verifier doing so reads the request that is signed here.
        ["a parameter repeated with the same value"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed};tag=\"renew\""]),
        ["a parameter repeated with another value"] = () =>
            Renew().WithParameter("nonce", Quoted(OtherNonce))
                .ToHttpRequest(signatureInput: [$"sig={Renew().SignatureParams};nonce={Quoted(OtherNonce)}"]),
        ["Signature-Input repeating sig in one field line"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed}, sig={signed}"]),
        ["Signature-Input repeating sig across two field lines"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed}", $"sig={signed}"]),
        ["Signature-Input with a second label in a second field line"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed}", $"sig2={signed}"]),

        // RFC 8941 §4.2 joins field lines with commas, and §4.2.2 fails a dictionary that ends in one.
        ["Signature-Input with an empty second field line"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed}", ""]),
        ["Signature-Input ending in a comma"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed},"]),

        ["Signature repeating sig in one field line"] = () =>
            RenewWithSignature(signature => [$"sig=:{signature}:, sig=:{signature}:"]),
        ["Signature repeating sig across two field lines"] = () =>
            RenewWithSignature(signature => [$"sig=:{signature}:", $"sig=:{signature}:"]),
        ["Signature with a second label in a second field line"] = () =>
            RenewWithSignature(signature => [$"sig=:{signature}:", $"sig2=:{signature}:"]),

        // RFC 8941 §4.2.7 lets a parser accept these forms, and they decode to the signed bytes.
        ["Signature without padding"] = () =>
            RenewWithSignature(signature => [$"sig=:{signature.TrimEnd('=')}:"]),
        ["Signature with non-zero pad bits"] = () =>
            RenewWithSignature(signature => [$"sig=:{Base64Forms.WithNonZeroPadBits(signature, urlSafe: false)}:"]),
        ["Signature in the base64url alphabet"] = () =>
        {
            TestRequest request = Renew();
            string signature = request.SignUntil(text => text.Contains('+') || text.Contains('/'));
            return request.ToHttpRequest(signature: [$"sig=:{Base64Forms.ToBase64UrlAlphabet(signature)}:"]);
        },
        ["a parameter on the Signature member"] = () =>
            RenewWithSignature(signature => [$"sig=:{signature}:;x=1"]),

        // Each of these keyid forms is no registered thumbprint, so without the rule the lookup draws identity_unknown.
        ["keyid with padding"] = () =>
            RenewWith("keyid", Quoted($"{DeviceA.Thumbprint}=")),
        ["keyid with non-zero pad bits"] = () =>
            RenewWith("keyid", Quoted(Base64Forms.WithNonZeroPadBits(DeviceA.Thumbprint, urlSafe: true))),
        ["keyid in the base64 alphabet"] = () =>
            RenewWith("keyid", Quoted(Base64Forms.ToBase64Alphabet(DeviceA.Thumbprint))),
        ["keyid of 31 bytes"] = () =>
            RenewWith("keyid", Quoted(Base64Forms.Base64Url(ThumbprintBytes()[..31]))),
        ["keyid of 33 bytes"] = () =>
            RenewWith("keyid", Quoted(Base64Forms.Base64Url([.. ThumbprintBytes(), 0]))),

        ["nonce with padding"] = () =>
            RenewWith("nonce", Quoted($"{TestRequest.DefaultNonce}==")),
        ["nonce with non-zero pad bits"] = () =>
            RenewWith("nonce", Quoted(Base64Forms.WithNonZeroPadBits(TestRequest.DefaultNonce, urlSafe: true))),
        ["nonce in the base64 alphabet"] = () =>
            RenewWith("nonce", Quoted(Base64Forms.ToBase64Alphabet(NonceWithDash))),
        ["nonce of 15 bytes"] = () =>
            RenewWith("nonce", Quoted(Base64Forms.Base64Url(new byte[15]))),
        ["nonce of 17 bytes"] = () =>
            RenewWith("nonce", Quoted(Base64Forms.Base64Url(new byte[17]))),

        ["created as a string"] = () => RenewWith("created", Quoted(Created)),
        ["created as a decimal"] = () => RenewWith("created", $"{Created}.0"),

        // RFC 8941 §3.3.1 allows at most 15 digits, leading zeros included,
        // and RFC 9421 §2.3 signs the integer as RFC 8941 §4.1.4 serializes it, without them.
        ["created of 16 digits"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed.Replace(CreatedParameter, $";created=000000{Created}")}"]),

        ["expires as a string"] = () => RenewWith("expires", Quoted(Expires)),
        ["expires as a decimal"] = () => RenewWith("expires", $"{Expires}.0"),
        ["alg as a token"] = () => RenewWith("alg", "ecdsa-p256-sha256"),

        // A token starts with a letter, which the thumbprint of device-c does.
        ["keyid as a token"] = () =>
            TestRequest.Valid(AgentOperation.Renew, Now, DeviceC)
                .WithParameter("keyid", DeviceC.Thumbprint)
                .ToHttpRequest(),
        ["nonce as a token"] = () => RenewWith("nonce", TestRequest.DefaultNonce),
        ["tag as a token"] = () => RenewWith("tag", "renew"),

        // RFC 8941 §4.2.5 escapes only a quote and a backslash,
        // so a lenient parser reads \n as n, and the tag as renew.
        ["tag with an escape RFC 8941 does not define"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed.Replace(TagParameter, @";tag=""re\new""")}"]),

        // No integer is a valid alg, keyid, nonce or tag, so these also break a rule on the value.
        ["alg as an integer"] = () => RenewWith("alg", "256"),
        ["keyid as an integer"] = () => RenewWith("keyid", "1"),
        ["nonce as an integer"] = () => RenewWith("nonce", "1"),
        ["tag as an integer"] = () => RenewWith("tag", "1"),

        // RFC 9421 §2.1.1 defines sf, which leaves this Content-Digest value unchanged in the base.
        ["a parameter on a covered component"] = () =>
            (Renew() with { Components = ["\"@method\"", "\"content-digest\";sf"] }).ToHttpRequest(),

        // A verifier that drops component parameters builds the base without them, which is the one signed here.
        ["a parameter on a covered component, not signed"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed.Replace("\"@method\"", "\"@method\";x")}"]),
    };

    private static readonly Dictionary<string, Func<TestRequest, SignedHttpRequest>> ContentDigestViolations = new()
    {
        ["absent"] = request => request.ToHttpRequest(contentDigest: []),
        ["with sha-256 and sha-512"] = request =>
            WithContentDigest(request, $"{request.ContentDigest}, {Sha512Digest(request.Body)}"),
        ["repeating sha-256"] = request =>
            WithContentDigest(request, $"{request.ContentDigest}, {request.ContentDigest}"),
        ["with a parameter"] = request =>
            WithContentDigest(request, $"{request.ContentDigest};x=1"),
        ["with only sha-512"] = request =>
            WithContentDigest(request, Sha512Digest(request.Body)),
        ["without padding"] = request =>
            WithContentDigest(request, $"sha-256=:{Sha256Base64(request.Body).TrimEnd('=')}:"),
        ["with non-zero pad bits"] = request =>
            WithContentDigest(
                request,
                $"sha-256=:{Base64Forms.WithNonZeroPadBits(Sha256Base64(request.Body), urlSafe: false)}:"),
    };

    private static readonly Dictionary<string, Func<SignedHttpRequest>> AcceptedForms = new()
    {
        ["the form the profile shows"] = () => Renew().ToHttpRequest(),
        ["parameters in reverse order"] = () =>
            (Renew() with { Parameters = [.. Renew().Parameters.Reverse()] }).ToHttpRequest(),
        ["created and expires after the other parameters"] = () =>
            (Renew() with { Parameters = [.. Renew().Parameters.OrderBy(p => p.Key is "created" or "expires")] })
                .ToHttpRequest(),

        // The signed base serializes the parsed member, so the white space RFC 8941 allows never reaches it.
        ["a space after each semicolon"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed.Replace(";", "; ")}"]),
        ["spaces inside the inner list"] = () =>
        {
            TestRequest request = Renew();
            return request.ToHttpRequest(
                signatureInput: [$"sig=(  {string.Join("   ", request.Components)} ){request.ParametersText}"]);
        },

        // A proxy that combines field lines can leave white space around each one; RFC 9421 §2.1 removes it.
        ["white space around each field line"] = () =>
        {
            TestRequest request = Renew();
            return request.ToHttpRequest(
                signatureInput: [$" \tsig={request.SignatureParams}\t "],
                signature: [$"\t sig=:{request.Sign()}: \t"],
                contentDigest: [$" {request.ContentDigest}\t "]);
        },

        // RFC 8941 §3.3.1 allows 15 digits, leading zeros included,
        // and RFC 9421 §2.3 signs the integer as RFC 8941 §4.1.4 serializes it, without them.
        ["created with leading zeros, in 15 digits"] = () =>
            RenewWithSignatureInput(signed => [$"sig={signed.Replace(CreatedParameter, $";created=00000{Created}")}"]),
    };

    // Signature-Input values that hold no inner list with its parameters;
    // most break RFC 8941 at their very end, where a parser that read on would leave the input.
    private static readonly Dictionary<string, Func<SignedHttpRequest>> MalformedSignatureInputs = new()
    {
        // RFC 9421 §3.2: the member is an inner list.
        ["an integer member"] = () => RenewWithSignatureInput(_ => ["sig=1"]),

        // RFC 8941 §4.2.3.2: a parameter has a key, and a key follows its equals sign with a bare item.
        ["a semicolon at the end"] = () => RenewWithSignatureInput(signed => [$"sig={signed};"]),
        ["created last, without a value"] = () => RenewWithLast("created", ""),

        // RFC 8941 §4.2.4: a minus sign is followed by a digit.
        ["created last, a minus sign alone"] = () => RenewWithLast("created", "-"),
        ["created last, a minus sign before a letter"] = () => RenewWithLast("created", "-x"),

        // RFC 8941 §4.2.5: a backslash is followed by the character it escapes, and a closing quote ends a string.
        ["tag last, unclosed, ending in a backslash"] = () => RenewWithLast("tag", "\"renew\\"),
    };

    public static TheoryData<string> StepOneViolationNames => new(StepOneViolations.Keys);

    public static TheoryData<AgentOperation, string> ContentDigestViolationCases
    {
        get
        {
            TheoryData<AgentOperation, string> cases = new();

            foreach (AgentOperation operation in new[] { AgentOperation.Renew, AgentOperation.CheckIn })
            {
                foreach (string violation in ContentDigestViolations.Keys)
                {
                    cases.Add(operation, violation);
                }
            }

            return cases;
        }
    }

    public static TheoryData<string> AcceptedFormNames => new(AcceptedForms.Keys);

    public static TheoryData<string> MalformedSignatureInputNames => new(MalformedSignatureInputs.Keys);

    private static KeyVector DeviceA => TestVectors.Instance.Key("device-a");

    private static KeyVector DeviceC => TestVectors.Instance.Key("device-c");

    private static string Created => Now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

    private static string Expires => (Now.ToUnixTimeSeconds() + 60).ToString(CultureInfo.InvariantCulture);

    // The created parameter of a renew request, as Signature-Input writes it.
    private static string CreatedParameter => $";created={Created}";

    // A verifier that keeps the last of repeated keys, decodes leniently, or reads a parameter of another type
    // accepts a request whose signature data a proxy, a log or another parser can read differently.
    [Theory]
    [MemberData(nameof(StepOneViolationNames))]
    public async Task CorrectlySignedRequestBreakingAStepOneRuleIsSignatureInvalid(string violation)
    {
        TestAuthority authority = new(Now);

        string outcome = await authority.OutcomeAsync(AgentOperation.Renew, StepOneViolations[violation]());

        Assert.Equal("signature_invalid", outcome);
    }

    // CONTRACT.md §6 step 1: for renew and check-in, Content-Digest holds exactly one member, sha-256,
    // without parameters, in canonical base64.
    [Theory]
    [MemberData(nameof(ContentDigestViolationCases))]
    public async Task CorrectlySignedRequestBreakingAContentDigestRuleIsSignatureInvalid(
        AgentOperation operation,
        string violation)
    {
        TestAuthority authority = new(Now);
        SignedHttpRequest request = ContentDigestViolations[violation](authority.Valid(operation));

        string outcome = await authority.OutcomeAsync(operation, request);

        Assert.Equal("signature_invalid", outcome);
    }

    // CONTRACT.md §6: parameters may appear in any order, and the verifier builds @signature-params
    // from the received member, so a verifier that copied the received text would reject these.
    [Theory]
    [MemberData(nameof(AcceptedFormNames))]
    public async Task RequestInAFormThatRfc8941AllowsIsAccepted(string form)
    {
        TestAuthority authority = new(Now);

        string outcome = await authority.OutcomeAsync(AgentOperation.Renew, AcceptedForms[form]());

        Assert.Equal("ok", outcome);
    }

    // CONTRACT.md §6 step 1: a malformed Signature-Input draws signature_invalid,
    // as a result rather than an exception, and records no nonce.
    [Theory]
    [MemberData(nameof(MalformedSignatureInputNames))]
    public async Task MalformedSignatureInputIsSignatureInvalid(string form)
    {
        TestAuthority authority = new(Now);

        string outcome = await authority.OutcomeAsync(AgentOperation.Renew, MalformedSignatureInputs[form]());

        Assert.Equal("signature_invalid", outcome);
        Assert.Empty(authority.Nonces.Calls);
    }

    // RFC 8941 §4.2.5: an escaped backslash decodes to one backslash, so the received tag is re\new,
    // which CONTRACT.md §6 step 2 rejects for renew.
    // The signature covers the tag renew, which a parser that dropped the escaped character would read.
    [Fact]
    public async Task TagWithAnEscapedBackslashIsAnotherTag()
    {
        TestAuthority authority = new(Now);
        SignedHttpRequest request =
            RenewWithSignatureInput(signed => [$"sig={signed.Replace(TagParameter, @";tag=""re\\new""")}"]);

        string outcome = await authority.OutcomeAsync(AgentOperation.Renew, request);

        Assert.Equal("signature_invalid", outcome);
        Assert.Empty(authority.Nonces.Calls);
    }

    private static TestRequest Renew()
    {
        return TestRequest.Valid(AgentOperation.Renew, Now);
    }

    private static SignedHttpRequest RenewWith(string parameter, string value)
    {
        return Renew().WithParameter(parameter, value).ToHttpRequest();
    }

    // The parameter moves to the end of Signature-Input, with the given serialized value.
    private static SignedHttpRequest RenewWithLast(string parameter, string value)
    {
        TestRequest request = Renew();
        TestRequest reordered = request with
        {
            Parameters = [.. request.Parameters.Where(p => p.Key != parameter), (parameter, value)],
        };
        return reordered.ToHttpRequest();
    }

    // The lines receive the signed value of @signature-params.
    private static SignedHttpRequest RenewWithSignatureInput(Func<string, IReadOnlyList<string>> lines)
    {
        TestRequest request = Renew();
        return request.ToHttpRequest(signatureInput: lines(request.SignatureParams));
    }

    // The lines receive the signature in canonical base64.
    private static SignedHttpRequest RenewWithSignature(Func<string, IReadOnlyList<string>> lines)
    {
        TestRequest request = Renew();
        return request.ToHttpRequest(signature: lines(request.Sign()));
    }

    // The value is both the field and the covered component, so the signature covers it.
    private static SignedHttpRequest WithContentDigest(TestRequest request, string value)
    {
        return (request with { ContentDigest = value }).ToHttpRequest();
    }

    private static string Quoted(string value)
    {
        return $"\"{value}\"";
    }

    private static byte[] ThumbprintBytes()
    {
        return Convert.FromBase64String($"{Base64Forms.ToBase64Alphabet(DeviceA.Thumbprint)}=");
    }

    private static string Sha256Base64(byte[] body)
    {
        return Convert.ToBase64String(SHA256.HashData(body));
    }

    // RFC 9530 §2.
    private static string Sha512Digest(byte[] body)
    {
        return $"sha-512=:{Convert.ToBase64String(SHA512.HashData(body))}:";
    }
}
