using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// Builds PKCS #10 requests (RFC 2986 §4) element by element,
/// so that a test can break one rule of a request and still sign it correctly.
/// </summary>
/// <remarks>
/// The builders join the elements they are given without checking them, so that a test can also break DER.
/// </remarks>
internal static class TestCsr
{
    // RFC 5480 §2.1.1 and §2.1.1.1.
    public const string IdEcPublicKey = "1.2.840.10045.2.1";
    public const string Secp256r1 = "1.2.840.10045.3.1.7";

    // RFC 5758 §3.2.
    public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";

    // An empty RDNSequence and an empty attribute set, the smallest values of two fields that RFC 2986 §4.1 requires.
    public static byte[] EmptySubject => [0x30, 0x00];

    public static byte[] EmptyAttributes => [0xA0, 0x00];

    public static byte[] Null => [0x05, 0x00];

    public static byte[] Tlv(byte tag, params byte[][] contents)
    {
        byte[] body = [.. contents.SelectMany(content => content)];

        return [tag, .. Length(body.Length), .. body];
    }

    /// <summary>
    /// An element whose length takes one octet more than DER allows (X.690 §10.1):
    /// the long form for a length below 128, or else a leading zero octet.
    /// </summary>
    public static byte[] TlvWithLongerLength(byte tag, byte[] contents)
    {
        byte[] length = Length(contents.Length);
        byte[] longer = length.Length == 1 ? [0x81, length[0]] : [(byte)(0x80 | length.Length), 0x00, .. length[1..]];

        return [tag, .. longer, .. contents];
    }

    public static byte[] Sequence(params byte[][] elements)
    {
        return Tlv(0x30, elements);
    }

    public static byte[] Integer(int value)
    {
        return Der(writer => writer.WriteInteger(value));
    }

    public static byte[] Oid(string oid)
    {
        return Der(writer => writer.WriteObjectIdentifier(oid));
    }

    public static byte[] BitString(byte[] value, byte unusedBits = 0)
    {
        return Tlv(0x03, [unusedBits], value);
    }

    /// <summary>
    /// The AlgorithmIdentifier of a P-256 key: <c>id-ecPublicKey</c> with the named curve <c>secp256r1</c>.
    /// </summary>
    public static byte[] P256Algorithm()
    {
        return Sequence(Oid(IdEcPublicKey), Oid(Secp256r1));
    }

    public static byte[] SubjectPublicKeyInfo(byte[] algorithm, byte[] publicKey, byte unusedBits = 0)
    {
        return Sequence(algorithm, BitString(publicKey, unusedBits));
    }

    /// <summary>
    /// The uncompressed point of the key (SEC 1 §2.3.3): <c>04</c>, then x and y.
    /// </summary>
    public static byte[] UncompressedPoint(ECDsa key)
    {
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);

        return [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];
    }

    public static byte[] RequestInfo(byte[] subjectPublicKeyInfo, byte[]? subject = null, byte[]? attributes = null)
    {
        return Sequence(Integer(0), subject ?? EmptySubject, subjectPublicKeyInfo, attributes ?? EmptyAttributes);
    }

    public static byte[] SignatureAlgorithm(string oid)
    {
        return Sequence(Oid(oid));
    }

    /// <summary>
    /// The DER ECDSA-Sig-Value (RFC 3279 §2.2.3) of the request info, with SHA-256 unless stated otherwise.
    /// </summary>
    public static byte[] Sign(ECDsa key, byte[] requestInfo, HashAlgorithmName? hash = null)
    {
        return key.SignData(requestInfo, hash ?? HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// A request for the request info, signed by the key with <c>ecdsa-with-SHA256</c> unless stated otherwise.
    /// </summary>
    public static byte[] Request(
        byte[] requestInfo,
        ECDsa signer,
        byte[]? signatureAlgorithm = null,
        HashAlgorithmName? hash = null)
    {
        return Sequence(
            requestInfo,
            signatureAlgorithm ?? SignatureAlgorithm(EcdsaWithSha256),
            BitString(Sign(signer, requestInfo, hash)));
    }

    /// <summary>
    /// A request for the key, signed by it, in the form that every rule accepts.
    /// </summary>
    public static byte[] For(ECDsa key)
    {
        return Request(RequestInfo(key.ExportSubjectPublicKeyInfo()), key);
    }

    // X.690 §8.1.3: the short form below 128, then the long form in as few octets as the length needs.
    private static byte[] Length(int length)
    {
        return length switch
        {
            < 0x80 => [(byte)length],
            <= 0xFF => [0x81, (byte)length],
            _ => [0x82, (byte)(length >> 8), (byte)length],
        };
    }

    private static byte[] Der(Action<AsnWriter> write)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        write(writer);

        return writer.Encode();
    }
}
