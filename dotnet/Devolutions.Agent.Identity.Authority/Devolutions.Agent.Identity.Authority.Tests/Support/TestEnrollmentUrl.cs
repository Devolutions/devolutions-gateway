using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// Builds the enrollment URL extension of CONTRACT.agent-identity.md §4 and the CSR attributes that request it.
/// </summary>
internal static class TestEnrollmentUrl
{
    // CONTRACT.agent-identity.md §4: the OID of the enrollment URL extension, under RFC 5612's documentation enterprise
    // number until the contract moves it.
    public const string Oid = "1.3.6.1.4.1.32473.1.1";

    // RFC 2985 §5.4.2: the extensionRequest attribute.
    public const string ExtensionRequestOid = "1.2.840.113549.1.9.14";

    /// <summary>
    /// The DER IA5String of a URL.
    /// </summary>
    public static byte[] IA5String(string url)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.IA5String, url);
        return writer.Encode();
    }

    /// <summary>
    /// An enrollment URL extension (RFC 5280 §4.1, <c>Extension</c>), non-critical, whose value is the given bytes.
    /// </summary>
    public static byte[] Extension(byte[] value, string oid = Oid)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteOctetString(value);
        }

        return writer.Encode();
    }

    /// <summary>
    /// The enrollment URL extension of a URL with its critical flag set.
    /// </summary>
    public static byte[] CriticalExtension(string url)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oid);
            writer.WriteBoolean(true);
            writer.WriteOctetString(IA5String(url));
        }

        return writer.Encode();
    }

    /// <summary>
    /// The <c>[0]</c> attributes of a CSR holding another attribute, given whole, then one extensionRequest.
    /// </summary>
    public static byte[] AttributesAfter(byte[] otherAttribute, params byte[][] extensions)
    {
        return TestCsr.Tlv(0xA0, otherAttribute, ExtensionRequestAttribute(extensions));
    }

    /// <summary>
    /// The same constructed element with an indefinite length (X.690 §8.1.3.6): its tag, 80, its contents, then 00 00.
    /// </summary>
    public static byte[] IndefiniteLength(byte[] element)
    {
        AsnDecoder.ReadEncodedValue(element, AsnEncodingRules.DER, out int contentOffset, out int contentLength, out _);

        return [element[0], 0x80, .. element.AsSpan(contentOffset, contentLength), 0x00, 0x00];
    }

    /// <summary>
    /// The enrollment URL extension of a URL, as the agent's CSR requests it.
    /// </summary>
    public static byte[] Extension(string url)
    {
        return Extension(IA5String(url));
    }

    /// <summary>
    /// The <c>[0]</c> attributes of a CSR (RFC 2986 §4) holding one extensionRequest of the given extensions.
    /// </summary>
    public static byte[] Attributes(params byte[][] extensions)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(ExtensionRequestOid);
            using (writer.PushSetOf())
            using (writer.PushSequence())
            {
                foreach (byte[] extension in extensions)
                {
                    writer.WriteEncodedValue(extension);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// The <c>[0]</c> attributes of a CSR holding one extensionRequest per given extension.
    /// </summary>
    public static byte[] AttributesWithAnExtensionRequestEach(params byte[][] extensions)
    {
        return TestCsr.Tlv(0xA0, [.. extensions.Select(extension => ExtensionRequestAttribute(extension))]);
    }

    // The one extensionRequest Attribute (RFC 2986 §4) that Attributes writes for the given extensions.
    private static byte[] ExtensionRequestAttribute(params byte[][] extensions)
    {
        return new AsnReader(Attributes(extensions), AsnEncodingRules.DER)
            .ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0))
            .ReadEncodedValue()
            .ToArray();
    }

    /// <summary>
    /// A CSR for the key, signed by it, with the given attributes.
    /// </summary>
    public static byte[] Request(ECDsa key, byte[] attributes)
    {
        return TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), attributes: attributes), key);
    }

    /// <summary>
    /// The CSR an agent sends: one extensionRequest holding the enrollment URL extension alone.
    /// </summary>
    public static byte[] Request(ECDsa key, string url)
    {
        return Request(key, Attributes(Extension(url)));
    }

    /// <summary>
    /// The validated CSR an agent sends for a new key, with the enrollment URL extension of a URL.
    /// </summary>
    public static CertificateSigningRequest Csr(string url)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return Csr(key, url);
    }

    /// <summary>
    /// The validated CSR an agent sends for a key, with the enrollment URL extension of a URL.
    /// </summary>
    public static CertificateSigningRequest Csr(ECDsa key, string url)
    {
        CsrValidationResult result = CertificateSigningRequest.Validate(Request(key, url));
        Assert.True(result.Succeeded, result.FailureDetail);
        return result.Csr;
    }

    /// <summary>
    /// A validated CSR for a new key that names no enrollment URL, with an empty attribute set.
    /// </summary>
    public static CertificateSigningRequest CsrWithoutEnrollmentUrl()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CsrValidationResult result = CertificateSigningRequest.Validate(TestCsr.For(key));
        Assert.True(result.Succeeded, result.FailureDetail);
        return result.Csr;
    }
}