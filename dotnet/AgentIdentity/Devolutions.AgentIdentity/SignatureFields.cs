using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using static Devolutions.AgentIdentity.StructuredField;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The <c>Signature-Input</c>, <c>Signature</c> and <c>Content-Digest</c> fields of a signed request,
/// parsed and checked against the profile of CONTRACT.md §6 step 1.
/// </summary>
/// <remarks>
/// One parse drives both the profile checks and the signature base,
/// so the parameters that the checks accept are exactly those the signature covers.
/// </remarks>
internal sealed class SignatureFields
{
    private const string Label = "sig";
    private const string Algorithm = "ecdsa-p256-sha256";
    private const string DigestAlgorithm = "sha-256";
    private const int ThumbprintLength = 32;
    private const int NonceLength = 16;

    private static readonly string[] ParameterNames = ["created", "expires", "nonce", "keyid", "alg", "tag"];

    private readonly InnerList _signatureInput;
    private readonly string? _contentDigestValue;

    private SignatureFields(
        InnerList signatureInput,
        long created,
        long expires,
        string nonce,
        string keyId,
        string tag,
        byte[] signature,
        byte[]? contentDigest,
        string? contentDigestValue)
    {
        _signatureInput = signatureInput;
        Created = created;
        Expires = expires;
        Nonce = nonce;
        KeyId = keyId;
        Tag = tag;
        Signature = signature;
        ContentDigest = contentDigest;
        _contentDigestValue = contentDigestValue;
    }

    public long Created { get; }

    public long Expires { get; }

    /// <summary>
    /// The nonce, as its canonical base64url text.
    /// </summary>
    public string Nonce { get; }

    /// <summary>
    /// The thumbprint of the signing certificate, as its canonical base64url text.
    /// </summary>
    public string KeyId { get; }

    public string Tag { get; }

    public byte[] Signature { get; }

    /// <summary>
    /// The SHA-256 digest that <c>Content-Digest</c> declares, for an operation that covers it; otherwise null.
    /// </summary>
    public byte[]? ContentDigest { get; }

    /// <summary>
    /// Parses and checks the signature fields of a request for an operation.
    /// </summary>
    /// <remarks>
    /// <c>Content-Digest</c> is read only when the operation covers it; otherwise it is ignored.
    /// The signature and digest lengths are not checked here, since verification checks them.
    /// On failure, <paramref name="failureDetail"/> names the rule that the fields break.
    /// </remarks>
    public static bool TryParse(
        SignedOperation operation,
        IReadOnlyList<string> signatureInput,
        IReadOnlyList<string> signature,
        IReadOnlyList<string> contentDigest,
        [NotNullWhen(true)] out SignatureFields? fields,
        [NotNullWhen(false)] out string? failureDetail)
    {
        fields = null;

        if (!TryParseSingleMember(
                signatureInput,
                "Signature-Input",
                Label,
                out MemberValue? inputMember,
                out failureDetail))
        {
            return false;
        }

        if (inputMember is not InnerList innerList)
        {
            failureDetail = "Step 1: the sig member of Signature-Input is not an inner list.";
            return false;
        }

        if (!innerList.Items.All(item => item is { Value: StringItem, Parameters.Count: 0 }))
        {
            failureDetail = "Step 1: a covered component is not a string without parameters.";
            return false;
        }

        IEnumerable<string> components = innerList.Items.Select(item => ((StringItem)item.Value).Value);
        if (!components.SequenceEqual(operation.CoveredComponents))
        {
            failureDetail = "Step 1: the covered components are not exactly those of the operation, in order.";
            return false;
        }

        // The parser rejects a repeated key, so six known keys are the six parameters, each once.
        IReadOnlyList<Parameter> parameters = innerList.Parameters;
        if (parameters.Count != ParameterNames.Length
            || !parameters.All(parameter => ParameterNames.Contains(parameter.Key)))
        {
            failureDetail = "Step 1: the parameters are not exactly created, expires, nonce, keyid, alg and tag.";
            return false;
        }

        if (Find(parameters, "created") is not IntegerItem created
            || Find(parameters, "expires") is not IntegerItem expires
            || Find(parameters, "nonce") is not StringItem nonce
            || Find(parameters, "keyid") is not StringItem keyId
            || Find(parameters, "alg") is not StringItem alg
            || Find(parameters, "tag") is not StringItem tag)
        {
            failureDetail = "Step 1: created or expires is not an integer, or another parameter is not a string.";
            return false;
        }

        // A malformed keyid fails here rather than at the certificate lookup,
        // so that an agent bug never draws the terminal identity_unknown.
        if (!StrictBase64.TryDecodeBase64Url(keyId.Value, out _, exactLength: ThumbprintLength))
        {
            failureDetail = "Step 1: keyid is not a certificate thumbprint in canonical base64url.";
            return false;
        }

        if (!StrictBase64.TryDecodeBase64Url(nonce.Value, out _, exactLength: NonceLength))
        {
            failureDetail = "Step 1: nonce is not 16 bytes in canonical base64url.";
            return false;
        }

        if (alg.Value != Algorithm)
        {
            failureDetail = "Step 1: alg is not ecdsa-p256-sha256.";
            return false;
        }

        if (!TryParseSingleMember(signature, "Signature", Label, out MemberValue? signatureMember, out failureDetail))
        {
            return false;
        }

        if (!TryDecodeByteSequence(signatureMember, out byte[]? signatureBytes))
        {
            failureDetail = "Step 1: the signature is not canonical base64 without parameters.";
            return false;
        }

        byte[]? digest = null;
        string? contentDigestValue = null;

        if (operation.CoversContentDigest)
        {
            if (!TryParseSingleMember(
                    contentDigest,
                    "Content-Digest",
                    DigestAlgorithm,
                    out MemberValue? digestMember,
                    out failureDetail))
            {
                return false;
            }

            if (!TryDecodeByteSequence(digestMember, out digest))
            {
                failureDetail = "Step 1: the sha-256 digest is not canonical base64 without parameters.";
                return false;
            }

            // RFC 9421 §2.1: a covered field contributes its combined value, as received.
            contentDigestValue = FieldLines.Combine(contentDigest);
        }

        fields = new SignatureFields(
            innerList,
            created.Value,
            expires.Value,
            nonce.Value,
            keyId.Value,
            tag.Value,
            signatureBytes,
            digest,
            contentDigestValue);
        failureDetail = null;
        return true;
    }

    /// <summary>
    /// Builds the signature base of RFC 9421 §2.5 for the request.
    /// </summary>
    /// <param name="method">The request method, as received, which is the value of <c>@method</c>.</param>
    /// <param name="signatureBase">The ASCII bytes of the signature base.</param>
    /// <returns>False when the method is not an RFC 9110 token, so <c>@method</c> has no value.</returns>
    public bool TryBuildSignatureBase(string method, [NotNullWhen(true)] out byte[]? signatureBase)
    {
        signatureBase = null;

        // RFC 9110 §9.1 defines a method as a token,
        // so the base stays ASCII and no component value can add a line of its own.
        if (!IsToken(method))
        {
            return false;
        }

        StringBuilder builder = new();

        foreach (Item component in _signatureInput.Items)
        {
            string name = ((StringItem)component.Value).Value;
            string value = name switch
            {
                SignedOperation.MethodComponent => method,
                SignedOperation.ContentDigestComponent => _contentDigestValue
                    ?? throw new UnreachableException("Content-Digest is covered but was not read."),
                _ => throw new UnreachableException("A covered component is outside the operation's profile."),
            };

            builder.Append(SerializeString(name)).Append(": ").Append(value).Append('\n');
        }

        builder.Append("\"@signature-params\": ");
        AppendSignatureParameters(builder);

        signatureBase = Encoding.ASCII.GetBytes(builder.ToString());
        return true;
    }

    // RFC 9421 §2.3: the value of @signature-params is the serialization of the received Signature-Input member,
    // with its parameters in received order, so the base never holds the received Signature-Input text.
    private void AppendSignatureParameters(StringBuilder builder)
    {
        builder.Append('(');
        builder.AppendJoin(' ', _signatureInput.Items.Select(item => SerializeString(((StringItem)item.Value).Value)));
        builder.Append(')');

        foreach (Parameter parameter in _signatureInput.Parameters)
        {
            builder.Append(';').Append(parameter.Key).Append('=').Append(parameter.Value switch
            {
                IntegerItem integer => SerializeInteger(integer.Value),
                StringItem text => SerializeString(text.Value),
                _ => throw new UnreachableException("A signature parameter is outside the profile."),
            });
        }
    }

    private static bool TryParseSingleMember(
        IReadOnlyList<string> fieldLines,
        string fieldName,
        string key,
        [NotNullWhen(true)] out MemberValue? value,
        [NotNullWhen(false)] out string? failureDetail)
    {
        value = null;

        if (fieldLines.Count == 0)
        {
            failureDetail = $"Step 1: {fieldName} is absent.";
            return false;
        }

        if (!TryParseDictionary(FieldLines.Combine(fieldLines), out IReadOnlyList<DictionaryMember>? dictionary))
        {
            failureDetail = $"Step 1: {fieldName} is not an RFC 8941 dictionary without repeated keys.";
            return false;
        }

        if (dictionary is not [{ Key: var memberKey, Value: var memberValue }] || memberKey != key)
        {
            failureDetail = $"Step 1: {fieldName} does not hold exactly one member, {key}.";
            return false;
        }

        value = memberValue;
        failureDetail = null;
        return true;
    }

    private static bool TryDecodeByteSequence(MemberValue value, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;

        return value is Item { Value: ByteSequenceItem sequence, Parameters.Count: 0 }
            && StrictBase64.TryDecodeBase64(sequence.Base64, out bytes);
    }

    private static BareItem? Find(IReadOnlyList<Parameter> parameters, string key)
    {
        return parameters.FirstOrDefault(parameter => parameter.Key == key)?.Value;
    }
}
