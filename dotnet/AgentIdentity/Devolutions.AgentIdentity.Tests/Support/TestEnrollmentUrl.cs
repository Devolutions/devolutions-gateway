using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// Builds the enrollment URL extension of CONTRACT.agent-identity.md §4 and the CSR attributes that request it.
/// </summary>
internal static class TestEnrollmentUrl
{
    // CONTRACT.agent-identity.md §4: the OID of the enrollment URL extension.
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