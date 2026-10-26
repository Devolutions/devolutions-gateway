using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// A PKCS #10 certificate signing request from an agent, reduced to the public key whose possession it proves.
/// </summary>
/// <remarks>
/// Only <see cref="Validate"/> and the request body parsers create instances,
/// so an instance always holds an uncompressed P-256 key that signed its request.
/// The request's subject, attributes and requested extensions are ignored and not kept,
/// since an identity is never derived from claims in a CSR, except the enrollment URL that its extensionRequest names,
/// which enrollment compares with the presented token (CONTRACT.agent-identity.md §4);
/// so the subject and the attributes need only be BER elements of their type,
/// and the rest of the request is DER, as CONTRACT.agent-identity.md §1 requires of a CSR.
/// </remarks>
public sealed class CertificateSigningRequest
{
    private const string IdEcPublicKey = "1.2.840.10045.2.1";
    private const string Secp256r1 = "1.2.840.10045.3.1.7";
    private const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";

    // RFC 2985 §5.4.2: the extensionRequest attribute.
    private const string ExtensionRequest = "1.2.840.113549.1.9.14";

    private static readonly Asn1Tag AttributesTag = new(TagClass.ContextSpecific, 0, isConstructed: true);

    // SEC 2 §2.4.2: secp256r1 is y² = x³ - 3x + b over the prime field of order p.
    private static readonly BigInteger P256Prime = Unsigned(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

    private static readonly BigInteger P256B = Unsigned(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

    private CertificateSigningRequest(byte[] subjectPublicKeyInfo, string? enrollmentUrl)
    {
        SubjectPublicKeyInfo = subjectPublicKeyInfo;
        SubjectPublicKeyInfoSha256 = SHA256.HashData(subjectPublicKeyInfo);
        EnrollmentUrl = enrollmentUrl;
    }

    /// <summary>
    /// The DER encoding of the request's <c>SubjectPublicKeyInfo</c>, exactly as the request holds it.
    /// </summary>
    /// <remarks>
    /// Validation accepts only the canonical encoding of an uncompressed P-256 key,
    /// so each key has exactly one <c>SubjectPublicKeyInfo</c>.
    /// </remarks>
    public ReadOnlyMemory<byte> SubjectPublicKeyInfo { get; }

    /// <summary>
    /// The SHA-256 digest of <see cref="SubjectPublicKeyInfo"/>, which identifies the key among every issued key.
    /// </summary>
    public ReadOnlyMemory<byte> SubjectPublicKeyInfoSha256 { get; }

    /// <summary>
    /// The value of the enrollment URL extension that the request's extensionRequest attribute holds,
    /// or null when the request names no single enrollment URL.
    /// </summary>
    /// <remarks>
    /// The value is read as text, as the request holds it.
    /// It is null when no extensionRequest holds the extension, when the extension appears more than once,
    /// or when its value is not one IA5String; a request whose attributes cannot be read names none either.
    /// <see cref="EnrollmentRules.Decide"/> compares it with the presented token's <c>u</c>,
    /// and a renewal ignores it (CONTRACT.agent-identity.md §4).
    /// </remarks>
    public string? EnrollmentUrl { get; }

    /// <summary>
    /// Validates a PKCS #10 certificate signing request (RFC 2986).
    /// </summary>
    /// <remarks>
    /// A valid request has version 0 and no trailing bytes, and is DER except for the subject and the attributes,
    /// which the server ignores but for the enrollment URL that <see cref="EnrollmentUrl"/> holds:
    /// each need only be a BER element of its type, a SEQUENCE and a constructed <c>[0]</c>,
    /// and the attributes never make the request invalid; the values of attributes other than extensionRequest stay
    /// unread.
    /// Its key is <c>id-ecPublicKey</c> on the named curve P-256, as an uncompressed point on the curve (RFC 5480).
    /// Its signature algorithm is <c>ecdsa-with-SHA256</c> without parameters (RFC 5758),
    /// and its signature verifies under its key over the exact bytes of its <c>certificationRequestInfo</c>.
    /// </remarks>
    /// <param name="der">The encoding of the request, DER except for its subject and attributes.</param>
    public static CsrValidationResult Validate(ReadOnlySpan<byte> der)
    {
        try
        {
            return Parse(der.ToArray());
        }
        catch (AsnContentException)
        {
            return CsrValidationResult.Failure("The CSR is not a DER-encoded PKCS #10 request.");
        }
    }

    // RFC 2986 §4:
    // CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature BIT STRING }
    // CertificationRequestInfo ::= SEQUENCE { version INTEGER, subject Name, subjectPKInfo, attributes [0] }
    private static CsrValidationResult Parse(byte[] der)
    {
        AsnReader outer = new(der, AsnEncodingRules.DER);
        AsnReader request = outer.ReadSequence();
        if (outer.HasData)
        {
            return CsrValidationResult.Failure("The CSR is followed by other bytes.");
        }

        ReadOnlyMemory<byte> requestInfo = request.PeekEncodedValue();
        ReadOnlyMemory<byte> fields = request.PeekContentBytes();
        _ = request.ReadSequence();
        AsnReader signatureAlgorithm = request.ReadSequence();
        byte[] signature = request.ReadBitString(out int signatureUnusedBits);
        request.ThrowIfNotEmpty();

        if (!AsnDecoder.TryReadInt32(fields.Span, AsnEncodingRules.DER, out int version, out int length) || version != 0)
        {
            return CsrValidationResult.Failure("The CSR version is not 0.");
        }

        // The subject and the attributes are read only as BER elements of their type, since nothing the server decides
        // depends on them but the enrollment URL, whose reading never makes the request invalid;
        // the self-signature still covers their bytes.
        fields = fields[length..];
        AsnDecoder.ReadSequence(fields.Span, AsnEncodingRules.BER, out _, out _, out length);

        fields = fields[length..];
        AsnDecoder.ReadSequence(fields.Span, AsnEncodingRules.DER, out _, out _, out length);
        ReadOnlyMemory<byte> subjectPublicKeyInfo = fields[..length];

        AsnReader attributes = new(fields[length..], AsnEncodingRules.BER);
        AsnReader attributeSet = attributes.ReadSetOf(skipSortOrderValidation: true, expectedTag: AttributesTag);
        attributes.ThrowIfNotEmpty();

        AsnReader subjectPublicKeyInfoReader = new AsnReader(subjectPublicKeyInfo, AsnEncodingRules.DER).ReadSequence();
        if (ReadP256Point(subjectPublicKeyInfoReader, out ECPoint point) is { } keyFailure)
        {
            return CsrValidationResult.Failure(keyFailure);
        }

        if (signatureAlgorithm.ReadObjectIdentifier() != EcdsaWithSha256 || signatureAlgorithm.HasData)
        {
            return CsrValidationResult.Failure(
                "The CSR signature algorithm is not ecdsa-with-SHA256 without parameters.");
        }

        if (signatureUnusedBits != 0 || !IsPositiveIntegerPair(signature))
        {
            return CsrValidationResult.Failure(
                "The CSR signature is not a DER ECDSA-Sig-Value of positive integers.");
        }

        using ECDsa key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = point });

        if (!key.VerifyData(
            requestInfo.Span,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence))
        {
            return CsrValidationResult.Failure("The CSR self-signature does not verify.");
        }

        return CsrValidationResult.Success(
            new CertificateSigningRequest(subjectPublicKeyInfo.ToArray(), ReadEnrollmentUrl(attributeSet)));
    }

    // RFC 2986 §4: Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY };
    // RFC 2985 §5.4.2: an extensionRequest value is Extensions ::= SEQUENCE OF Extension;
    // RFC 5280 §4.1: Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
    // Returns the value of the one enrollment URL extension among the requested extensions,
    // or null when there is none, there are several, or the attributes cannot be read,
    // since the server otherwise ignores the attributes (CONTRACT.agent-identity.md §4).
    private static string? ReadEnrollmentUrl(AsnReader attributeSet)
    {
        try
        {
            List<byte[]> values = [];

            while (attributeSet.HasData)
            {
                AsnReader attribute = attributeSet.ReadSequence();

                // The values of every other attribute stay unread, since the server ignores them.
                if (attribute.ReadObjectIdentifier() != ExtensionRequest)
                {
                    continue;
                }

                AsnReader attributeValues = attribute.ReadSetOf(skipSortOrderValidation: true);

                while (attributeValues.HasData)
                {
                    AsnReader extensions = attributeValues.ReadSequence();

                    while (extensions.HasData)
                    {
                        AsnReader extension = extensions.ReadSequence();
                        string id = extension.ReadObjectIdentifier();
                        if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                        {
                            _ = extension.ReadBoolean();
                        }

                        byte[] value = extension.ReadOctetString();
                        if (id == EnrollmentUrlExtension.Oid)
                        {
                            values.Add(value);
                        }
                    }
                }
            }

            return values is [byte[] single] ? EnrollmentUrlExtension.ReadValue(single) : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    // RFC 5480 §2: SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING },
    // with id-ecPublicKey, the namedCurve secp256r1 and an ECPoint whose octets are the bits of the BIT STRING.
    // Returns why the key is not an uncompressed P-256 point, or null.
    private static string? ReadP256Point(AsnReader subjectPublicKeyInfo, out ECPoint point)
    {
        point = default;

        AsnReader algorithm = subjectPublicKeyInfo.ReadSequence();
        byte[] encodedPoint = subjectPublicKeyInfo.ReadBitString(out int unusedBits);
        subjectPublicKeyInfo.ThrowIfNotEmpty();

        if (algorithm.ReadObjectIdentifier() != IdEcPublicKey)
        {
            return "The CSR key is not an id-ecPublicKey key.";
        }

        // RFC 5480 §2.1.1: the parameters are present and use the namedCurve choice.
        if (!algorithm.HasData
            || !algorithm.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier)
            || algorithm.ReadObjectIdentifier() != Secp256r1
            || algorithm.HasData)
        {
            return "The CSR key is not on the named curve P-256.";
        }

        // SEC 1 §2.3.3: the uncompressed form is 04, then x and y in 32 octets each.
        // Requiring it gives each key exactly one encoding, and so one SubjectPublicKeyInfo SHA-256.
        if (unusedBits != 0 || encodedPoint.Length != 65 || encodedPoint[0] != 0x04)
        {
            return "The CSR key is not an uncompressed P-256 point.";
        }

        byte[] x = encodedPoint[1..33];
        byte[] y = encodedPoint[33..];

        if (!IsOnP256(x, y))
        {
            return "The CSR key is not a point on P-256.";
        }

        point = new ECPoint { X = x, Y = y };
        return null;
    }

    // Checks the curve equation itself rather than relying on the platform's key import,
    // which throws an exception of a platform-specific type for a point off the curve.
    private static bool IsOnP256(byte[] x, byte[] y)
    {
        BigInteger bx = new(x, isUnsigned: true, isBigEndian: true);
        BigInteger by = new(y, isUnsigned: true, isBigEndian: true);

        if (bx >= P256Prime || by >= P256Prime)
        {
            return false;
        }

        BigInteger left = by * by % P256Prime;
        BigInteger right = BigInteger.Remainder((bx * bx * bx) - (3 * bx) + P256B, P256Prime);

        return left == right;
    }

    // RFC 3279 §2.2.3: Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }, where r and s are positive.
    // The platform verifier reads each INTEGER as unsigned, so it would also accept an r or s that DER makes negative.
    private static bool IsPositiveIntegerPair(byte[] signature)
    {
        AsnReader outer = new(signature, AsnEncodingRules.DER);
        AsnReader sequence = outer.ReadSequence();
        BigInteger r = sequence.ReadInteger();
        BigInteger s = sequence.ReadInteger();
        sequence.ThrowIfNotEmpty();
        outer.ThrowIfNotEmpty();

        return r.Sign > 0 && s.Sign > 0;
    }

    private static BigInteger Unsigned(string hex)
    {
        return new BigInteger(Convert.FromHexString(hex), isUnsigned: true, isBigEndian: true);
    }
}
