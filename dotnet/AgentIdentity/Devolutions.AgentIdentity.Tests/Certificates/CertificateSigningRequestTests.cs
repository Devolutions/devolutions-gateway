using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity.Tests;

public class CertificateSigningRequestTests
{
    // RFC 5480 §2: the DER SubjectPublicKeyInfo of a P-256 key up to its uncompressed point,
    // SEQUENCE { SEQUENCE { id-ecPublicKey, secp256r1 }, BIT STRING of 66 octets with no unused bits }.
    internal static readonly byte[] P256SubjectPublicKeyInfoPrefix =
        Convert.FromHexString("3059301306072A8648CE3D020106082A8648CE3D030107034200");

    // SEC 2 §2.4.2: P-256 is y² = x³ - 3x + b over the prime field of order p.
    private static readonly BigInteger P256Prime = Unsigned(
        Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));

    private static readonly BigInteger P256B = Unsigned(
        Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"));

    // CONTRACT.agent-identity.md §4: the server ignores the CSR's subject and attributes,
    // including requested extensions, and security invariant 2 lets a CSR supply only a verified public key.
    private static readonly Dictionary<string, Func<ECDsa, byte[]>> RequestsWithIgnoredContents = new()
    {
        ["subject, attributes and extensions"] = key =>
        {
            CertificateRequest request = new("CN=Administrator, O=Another Identity", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            SubjectAlternativeNameBuilder alternativeName = new();
            alternativeName.AddUri(new Uri("urn:uuid:5d2e8f14-3c61-4b7a-8e29-6a0f4c1d7b02"));
            request.CertificateExtensions.Add(alternativeName.Build());
            // RFC 2985 §5.4.1 challengePassword, a DirectoryString.
            byte[] challengePassword = [0x0C, 0x02, 0x70, 0x77];
            request.OtherRequestAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.7", challengePassword));
            return request.CreateSigningRequest();
        },

        // The agent's CSR carries an empty attribute set, A0 00.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["empty attribute set"] = key =>
            TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), attributes: [0xA0, 0x00]), key),

        // CONTRACT.agent-identity.md §4: the server ignores an extensionRequest with an empty Extensions list,
        // which common CSR builders emit although RFC 5280 §4.1 gives Extensions SIZE (1..MAX).
        // The attribute is the PKCS #9 extensionRequest (RFC 2985 §5.4.2) with one value, an empty SEQUENCE.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["extensionRequest with empty Extensions"] = key =>
        {
            byte[] extensionRequest = TestCsr.Sequence(
                TestCsr.Oid("1.2.840.113549.1.9.14"),
                TestCsr.Tlv(0x31, TestCsr.Sequence()));
            byte[] info = TestCsr.RequestInfo(
                key.ExportSubjectPublicKeyInfo(),
                attributes: TestCsr.Tlv(0xA0, extensionRequest));
            return TestCsr.Request(info, key);
        },

        // CONTRACT.agent-identity.md §4: attributes need no "canonical DER form,
        // such as a sorted `SET OF`" (X.690 §11.6).
        // Their encodings first differ in the last arc of the OIDs, 04 then 03, so the set descends.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["attributes out of DER order"] = key =>
        {
            static byte[] Attribute(string oid) =>
                TestCsr.Sequence(TestCsr.Oid(oid), TestCsr.Tlv(0x31, TestCsr.Tlv(0x0C, "a"u8.ToArray())));
            byte[] info = TestCsr.RequestInfo(
                key.ExportSubjectPublicKeyInfo(),
                attributes: TestCsr.Tlv(0xA0, Attribute("1.2.4"), Attribute("1.2.3")));
            return TestCsr.Request(info, key);
        },

        // The subject need not be DER, which writes its length in the fewest octets (X.690 §10.1).
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["subject with a longer length"] = key =>
        {
            byte[] subject = TestCsr.TlvWithLongerLength(0x30, []);
            return TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject), key);
        },

        // Nor need anything inside it, here a relative distinguished name CN=a whose length takes one octet more.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["subject with a longer length inside"] = key =>
        {
            byte[] commonName = TestCsr.Sequence(TestCsr.Oid("2.5.4.3"), TestCsr.Tlv(0x0C, "a"u8.ToArray()));
            byte[] subject = TestCsr.Sequence(TestCsr.TlvWithLongerLength(0x31, commonName));
            return TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject), key);
        },

        // Nor need the attributes, here an empty attribute set whose length takes one octet more.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["attributes with a longer length"] = key =>
        {
            byte[] attributes = TestCsr.TlvWithLongerLength(0xA0, []);
            return TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), attributes: attributes), key);
        },
    };

    // Requests that break a rule of the CSR profile, by name.
    private static readonly Dictionary<string, Func<byte[]>> InvalidRequests = new()
    {
        // None of these bytes is a CertificationRequest.
        // oracle: spec RFC 2986 §4
        ["no bytes"] = () => [],
        // oracle: spec RFC 2986 §4
        ["a zero octet"] = () => [0x00],
        // oracle: spec RFC 2986 §4
        ["an empty SEQUENCE"] = () => [0x30, 0x00],
        // oracle: spec RFC 2986 §4
        ["a SEQUENCE of a truncated SEQUENCE"] = () => [0x30, 0x03, 0x30, 0x01, 0x0A],

        // A CSR is DER, the encoding of one request.
        // Bytes after the request would give one request many encodings.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        ["trailing bytes"] = () => [.. AcceptedValidVector(), 0x00],

        // X.690 §10.1: DER writes each length in the fewest octets.
        // A CSR is DER, except for the subject and the attributes, which the server ignores.
        // The self-signature covers only the request info, so the request still verifies with a longer outer length.
        // oracle: spec X.690 §10.1
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        ["CertificationRequest with a longer length"] = () => TestCsr.TlvWithLongerLength(0x30, ValidVectorContents()),

        // The same for the request info and its version, which a test can only change by signing the request again.
        // oracle: spec X.690 §10.1
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        ["CertificationRequestInfo with a longer length"] = WithNewKey(key =>
        {
            byte[] spki = key.ExportSubjectPublicKeyInfo();
            byte[] info = TestCsr.TlvWithLongerLength(
                0x30,
                [.. TestCsr.Integer(0), .. TestCsr.EmptySubject, .. spki, .. TestCsr.EmptyAttributes]);
            return TestCsr.Request(info, key);
        }),
        // oracle: spec X.690 §10.1
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        ["version with a longer length"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.Sequence(
                TestCsr.TlvWithLongerLength(0x02, [0x00]),
                TestCsr.EmptySubject,
                key.ExportSubjectPublicKeyInfo(),
                TestCsr.EmptyAttributes);
            return TestCsr.Request(info, key);
        }),

        // Another encoding of the key's SubjectPublicKeyInfo would give the key a second SHA-256.
        // oracle: spec X.690 §10.1
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["SubjectPublicKeyInfo with a longer length"] = WithNewKey(key =>
        {
            byte[] spki = TestCsr.TlvWithLongerLength(
                0x30,
                [.. TestCsr.P256Algorithm(), .. TestCsr.BitString(TestCsr.UncompressedPoint(key))]);
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        }),

        // DER uses the definite form of length.
        // oracle: spec X.690 §10.1
        ["indefinite length"] = () => [0x30, 0x80, .. ValidVectorContents(), 0x00, 0x00],

        // version is v1, encoded 0.
        // oracle: spec RFC 2986 §4.1
        ["version 1"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.Sequence(
                TestCsr.Integer(1),
                TestCsr.EmptySubject,
                key.ExportSubjectPublicKeyInfo(),
                TestCsr.EmptyAttributes);
            return TestCsr.Request(info, key);
        }),

        // The subject is a Name, which is a SEQUENCE.
        // oracle: spec RFC 2986 §4.1
        // oracle: spec RFC 5280 §4.1.2.4
        ["subject that is not a SEQUENCE"] = WithNewKey(key =>
            TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject: [0x31, 0x00]), key)),

        // attributes is a required field, a constructed [0] IMPLICIT SET OF Attribute.
        // oracle: spec RFC 2986 §4.1
        ["request info without attributes"] = WithNewKey(key => RequestWithAttributes(key, [])),

        // The module of Appendix A uses IMPLICIT TAGS,
        // and X.690 8.14.4 a) keeps an implicitly tagged SET OF constructed,
        // so the attributes written primitive, 80 00, are not the required field.
        // oracle: spec RFC 2986 §4.1
        // oracle: spec RFC 2986 §A
        // oracle: spec X.690 §8.14
        ["request info with primitive attributes"] = WithNewKey(key => RequestWithAttributes(key, [0x80, 0x00])),

        // RFC 2986 §4 defines exactly the fields of each SEQUENCE, with no extension marker,
        // and RFC 5480 §2 those of SubjectPublicKeyInfo and of its AlgorithmIdentifier.
        // oracle: spec RFC 2986 §4.1
        ["CertificationRequestInfo with an extra element"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.Sequence(
                TestCsr.Integer(0),
                TestCsr.EmptySubject,
                key.ExportSubjectPublicKeyInfo(),
                TestCsr.EmptyAttributes,
                TestCsr.Null);
            return TestCsr.Request(info, key);
        }),
        // oracle: spec RFC 2986 §4.2
        ["CertificationRequest with an extra element"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
            return TestCsr.Sequence(
                info,
                TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
                TestCsr.BitString(TestCsr.Sign(key, info)),
                TestCsr.Null);
        }),

        // Another element would give the key a second SubjectPublicKeyInfo, and so a second SHA-256.
        // oracle: spec RFC 5480 §2
        ["AlgorithmIdentifier of the key with an extra element"] = WithNewKey(key =>
        {
            byte[] algorithm = TestCsr.Sequence(
                TestCsr.Oid(TestCsr.IdEcPublicKey),
                TestCsr.Oid(TestCsr.Secp256r1),
                TestCsr.Null);
            byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        }),
        // oracle: spec RFC 5480 §2
        ["SubjectPublicKeyInfo with an extra element"] = WithNewKey(key =>
        {
            byte[] spki = TestCsr.Sequence(
                TestCsr.P256Algorithm(),
                TestCsr.BitString(TestCsr.UncompressedPoint(key)),
                TestCsr.Null);
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        }),

        // The key is a P-256 key.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["P-384 key"] = () =>
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            return TestCsr.For(key);
        },

        // secp256k1 (SEC 2 §2.4.1) points also take 65 octets uncompressed, so only the curve name tells them apart.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["P-256 point named secp256k1"] = WithNewKey(key =>
        {
            byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), TestCsr.Oid("1.3.132.0.10"));
            byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        }),

        // RFC 5480 §2.1.2: id-ecDH restricts the key to key agreement;
        // CONTRACT.agent-identity.md §4 needs a signing key.
        // oracle: spec RFC 5480 §2.1.2
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["key restricted to key agreement"] = WithNewKey(key =>
        {
            byte[] algorithm = TestCsr.Sequence(TestCsr.Oid("1.3.132.1.12"), TestCsr.Oid(TestCsr.Secp256r1));
            byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        }),

        // RFC 5480 §2.1.1: the parameters of id-ecPublicKey MUST be present, and only namedCurve is allowed.
        // oracle: spec RFC 5480 §2.1.1
        ["key without curve parameters"] = WithNewKey(key => RequestWithKeyAlgorithm(
            key,
            TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey)))),
        // oracle: spec RFC 5480 §2.1.1
        ["key with implicitCurve"] = WithNewKey(key => RequestWithKeyAlgorithm(
            key,
            TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), TestCsr.Null))),

        // The specified form of the P-256 domain parameters,
        // which .NET writes for a key imported with explicit parameters.
        // oracle: spec RFC 5480 §2.1.1
        ["key with specifiedCurve"] = WithNewKey(key => RequestWithKeyAlgorithm(
            key,
            TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), P256SpecifiedDomain()))),

        // CONTRACT.agent-identity.md §4: an uncompressed point, so that each key has exactly one SubjectPublicKeyInfo.
        // The compressed form is 02 for an even y or 03 for an odd y, then x.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec SEC 1 §2.3.3
        ["compressed point"] = WithNewKey(key =>
        {
            ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
            return RequestWithPoint(key, [(byte)(0x02 | (parameters.Q.Y![^1] & 1)), .. parameters.Q.X!]);
        }),

        // ANSI X9.62 also defines a hybrid form, 06 or 07 then both coordinates; RFC 5480 §2.2 rejects it.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec RFC 5480 §2.2
        ["hybrid point"] = WithNewKey(key =>
        {
            byte[] point = TestCsr.UncompressedPoint(key);
            point[0] = (byte)(0x06 | (point[^1] & 1));
            return RequestWithPoint(key, point);
        }),

        // The uncompressed form is 04, then x and y in 32 octets each, 65 octets in all.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec SEC 1 §2.3.3
        ["point without its form octet"] = WithNewKey(key =>
            RequestWithPoint(key, TestCsr.UncompressedPoint(key)[1..])),
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec SEC 1 §2.3.3
        ["point with an extra octet"] = WithNewKey(key =>
            RequestWithPoint(key, [.. TestCsr.UncompressedPoint(key), 0x00])),

        // The point at infinity is the single octet 00.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec SEC 1 §2.3.3
        ["point at infinity"] = WithNewKey(key => RequestWithPoint(key, [0x00])),

        // The key is a point on P-256.
        // Flipping the low bit of y leaves the point off the curve,
        // since the only other point with the same x has y' = p - y, which is y + 1 or y - 1 only for y = (p ± 1) / 2.
        // No private key exists for such a point, so the key whose point was altered signs the request.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["point off the curve"] = () =>
        {
            using ECDsa key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(TestVectors.Instance.Key("device-a").PrivateKeyPkcs8, out _);
            byte[] point = TestCsr.UncompressedPoint(key);
            point[^1] ^= 0x01;
            return RequestWithPoint(key, point);
        },

        // SEC 1 §3.2.2.1: the coordinates of a public key are integers below p,
        // and CONTRACT.agent-identity.md §4 gives a key that is not a P-256 point invalid_request, not an exception.
        // Each point is on the curve modulo p, so only the range of its coordinates rejects it;
        // a platform's key import throws an exception of a platform-specific type for such a point.
        // x = p, which is 0 modulo p, and y a square root of b modulo p.
        // oracle: spec SEC 1 §3.2.2.1
        ["point with x out of the field"] = () => RequestWithPointOnP256ModuloP(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "66485C780E2F83D72433BD5D84A06BB6541C2AF31DAE871728BF856A174F93F4"),

        // y = p + 1, which is 1 modulo p, and x a root of x³ - 3x + b - 1 modulo p.
        // oracle: spec SEC 1 §3.2.2.1
        ["point with y out of the field"] = () => RequestWithPointOnP256ModuloP(
            "09E78D4EF60D05F750F6636209092BC43CBDD6B47E11A9DE20A9FEB2A50BB96C",
            "FFFFFFFF00000001000000000000000000000001000000000000000000000000"),

        // X.690 §11.2.1: DER requires an unused bit to be zero, so each BIT STRING is one whose last octet is even.
        // The key needs an uncompressed P-256 point, else invalid_request.
        // The octets of the point become the bits of the BIT STRING, so none is unused.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec RFC 5480 §2.2
        ["subjectPublicKey with unused bits"] = () =>
        {
            using ECDsa key = NewKeyWhere(point => (point[^1] & 1) == 0);
            byte[] spki = TestCsr.SubjectPublicKeyInfo(
                TestCsr.P256Algorithm(),
                TestCsr.UncompressedPoint(key),
                unusedBits: 1);
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        },

        // The request needs a verified self-signature, else invalid_request.
        // The BIT STRING holds the octets of the DER Ecdsa-Sig-Value, so none is unused.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec RFC 3279 §2.2
        // oracle: spec RFC 3279 §2.2.3
        ["signature with unused bits"] = WithNewKey(key =>
        {
            (byte[] info, byte[] signature) = SignedInfoWhere(key, (_, s) => (s[^1] & 1) == 0);
            return TestCsr.Sequence(
                info,
                TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
                TestCsr.BitString(signature, unusedBits: 1));
        }),

        // The signature algorithm is ecdsa-with-SHA256, even when the signature verifies under it.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["another signature algorithm over a SHA-256 signature"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
            byte[] algorithm = TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha384);
            return TestCsr.Request(info, key, algorithm, HashAlgorithmName.SHA256);
        }),

        // The AlgorithmIdentifier of ecdsa-with-SHA256 MUST omit the parameters.
        // oracle: spec RFC 5758 §3.2
        ["signature algorithm with NULL parameters"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
            byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.EcdsaWithSha256), TestCsr.Null);
            return TestCsr.Request(info, key, algorithm);
        }),

        // Security invariant 1: the self-signature is the proof of possession of the request's key.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        ["request signed by another key"] = WithNewKey(key =>
        {
            using ECDsa other = NewKey();
            return TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo()), other);
        }),

        // The signature is a DER ECDSA-Sig-Value, not the 64-octet r‖s form that request signatures use.
        // oracle: spec RFC 5758 §3.2
        // oracle: spec RFC 3279 §2.2.3
        ["signature in fixed-field form"] = WithNewKey(key =>
        {
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
            byte[] signature = key.SignData(
                info,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return TestCsr.Sequence(
                info,
                TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
                TestCsr.BitString(signature));
        }),

        // SEC 1 4.1.4 step 1: a verifier outputs "invalid" unless r and s are both in [1, n - 1], so both are positive.
        // An r whose top bit is set needs a leading zero octet; without it, DER reads a negative number,
        // which the BCL verifier accepts as the unsigned value, so only the library's own check rejects it.
        // An r that would start FF after the zero octet is skipped, since its negative form would not be minimal DER.
        // oracle: spec SEC 1 §4.1.4
        // oracle: spec X.690 §8.3
        ["signature with a negative r"] = WithNewKey(key =>
        {
            (byte[] info, byte[] signature) = SignedInfoWhere(key, (r, _) => r.Length == 33 && r[1] != 0xFF);
            (byte[] r, byte[] s) = ReadSignature(signature);
            byte[] negative = TestCsr.Sequence(TestCsr.Tlv(0x02, r[1..]), TestCsr.Tlv(0x02, s));
            // oracle: reference .NET ECDsa.VerifyData
            Assert.True(
                key.VerifyData(info, negative, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
            return TestCsr.Sequence(
                info,
                TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
                TestCsr.BitString(negative));
        }),
    };

    public static TheoryData<string> RequestWithIgnoredContentsNames => new(RequestsWithIgnoredContents.Keys);

    public static TheoryData<string> InvalidRequestNames => new(InvalidRequests.Keys);

    // test-vectors.json csr.<name>.expected, the outcome CONTRACT.agent-identity.md §4 gives each request.
    // oracle: reference docs/agent-identity/test-vectors.json csr
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Theory]
    [MemberData(nameof(VectorData.CsrNames), MemberType = typeof(VectorData))]
    public void CsrVectorHasItsExpectedOutcome(string name)
    {
        CsrVector vector = TestVectors.Instance.Csr[name];

        CsrValidationResult result = CertificateSigningRequest.Validate(vector.Csr);

        Assert.Equal(vector.Expected, result.Succeeded ? "ok" : result.Error.Code.ToWireValue());
    }

    // test-vectors.json csr.valid.public_key_sec1, after the RFC 5480 §2 prefix of a P-256 SubjectPublicKeyInfo.
    // oracle: reference docs/agent-identity/test-vectors.json csr.valid
    // oracle: spec RFC 5480 §2
    [Fact]
    public void ValidVectorYieldsTheSubjectPublicKeyInfoOfItsKey()
    {
        CsrVector vector = TestVectors.Instance.Csr["valid"];
        Assert.NotNull(vector.PublicKeySec1);
        byte[] expected = [.. P256SubjectPublicKeyInfoPrefix, .. vector.PublicKeySec1];

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(vector.Csr));

        Assert.Equal(expected, csr.SubjectPublicKeyInfo.ToArray());
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
        Assert.Equal(SHA256.HashData(expected), csr.SubjectPublicKeyInfoSha256.ToArray());
    }

    // A request written by .NET rather than by the test builder.
    // A P-256 key and ecdsa-with-SHA256, the profile .NET writes for this key.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void AcceptsRequestWrittenByDotNet()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] der = new CertificateRequest("CN=ignored", key, HashAlgorithmName.SHA256).CreateSigningRequest();

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(der));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Theory]
    [MemberData(nameof(RequestWithIgnoredContentsNames))]
    public void AcceptsAnySubjectAndAttributes(string request)
    {
        using ECDsa key = NewKey();

        CertificateSigningRequest csr =
            AssertValid(CertificateSigningRequest.Validate(RequestsWithIgnoredContents[request](key)));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // The server reads the enrollment URL extension from the CSR's extensionRequest and ignores every other attribute
    // or requested extension; a CSR that names no single enrollment URL is still valid, and enrollment refuses it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Theory]
    [MemberData(nameof(EnrollmentUrlRequestNames))]
    public void ReadsTheEnrollmentUrlOfTheExtensionRequest(string request)
    {
        (Func<ECDsa, byte[]> build, string? expected) = EnrollmentUrlRequests[request];
        using ECDsa key = NewKey();

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(build(key)));

        Assert.Equal(expected, csr.EnrollmentUrl);
    }

    public static TheoryData<string> EnrollmentUrlRequestNames => new(EnrollmentUrlRequests.Keys);

    // Requests by what their attributes hold, with the enrollment URL each names, or null when they name none.
    private static Dictionary<string, (Func<ECDsa, byte[]> Build, string? Expected)> EnrollmentUrlRequests => new()
    {
        // The agent's CSR: one extensionRequest holding the enrollment URL extension alone.
        ["the extension alone"] = (key => TestEnrollmentUrl.Request(key, "https://host/dvls"), "https://host/dvls"),
        // The value is read as it is; whether it matches the token is the enrollment rules' to decide.
        ["a value with a trailing slash"] =
            (key => TestEnrollmentUrl.Request(key, "https://host/dvls/"), "https://host/dvls/"),
        ["the extension among other requested extensions"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(
                    TestEnrollmentUrl.Extension(
                        new X509BasicConstraintsExtension(true, false, 0, true).RawData,
                        "2.5.29.19"),
                    TestEnrollmentUrl.Extension("https://host/dvls"))),
            "https://host/dvls"),
        ["the extension written by .NET"] = (
            key =>
            {
                CertificateRequest request = new("CN=agent", key, HashAlgorithmName.SHA256);
                request.CertificateExtensions.Add(
                    new X509Extension(TestEnrollmentUrl.Oid, TestEnrollmentUrl.IA5String("https://host/dvls"), false));
                return request.CreateSigningRequest();
            },
            "https://host/dvls"),
        // A critical flag on a requested extension changes nothing the server reads.
        // oracle: spec RFC 5280 §4.1
        ["the extension marked critical"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(TestEnrollmentUrl.CriticalExtension("https://host/dvls"))),
            "https://host/dvls"),
        // The server ignores every other attribute, whatever its contents.
        ["after another attribute whose values are not a SET"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.AttributesAfter(
                    TestCsr.Sequence(TestCsr.Oid("1.2.840.113549.1.9.7"), [0x04, 0x00]),
                    TestEnrollmentUrl.Extension("https://host/dvls"))),
            "https://host/dvls"),
        // The attributes need not be DER, such as an indefinite length.
        ["in an attribute set of indefinite length"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.IndefiniteLength(
                    TestEnrollmentUrl.Attributes(TestEnrollmentUrl.Extension("https://host/dvls")))),
            "https://host/dvls"),
        // The agent's CSR before it named an enrollment URL: an empty attribute set, A0 00.
        ["no attributes"] = (TestCsr.For, null),
        // An attribute that is not a SEQUENCE names nothing, and the server ignores it.
        ["an attribute that is not a SEQUENCE"] =
            (key => TestEnrollmentUrl.Request(key, [0xA0, 0x02, 0x04, 0x00]), null),
        ["an extensionRequest without the extension"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(
                    TestEnrollmentUrl.Extension(TestEnrollmentUrl.IA5String("x"), "2.5.29.17"))),
            null),
        // A leaf carries the extension exactly once, so a request naming two values names no single one.
        ["the extension twice"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(
                    TestEnrollmentUrl.Extension("https://host/dvls"),
                    TestEnrollmentUrl.Extension("https://host/dvls"))),
            null),
        // The extension holds an IA5String.
        ["a UTF8String value"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(TestEnrollmentUrl.Extension([0x0C, 0x04, .. "host"u8]))),
            null),
        // An IA5String holds the characters 0 to 127 (X.680 §41).
        ["an IA5String with a byte above 127"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(TestEnrollmentUrl.Extension([0x16, 0x01, 0x80]))),
            null),
        ["an IA5String followed by other bytes"] = (
            key => TestEnrollmentUrl.Request(
                key,
                TestEnrollmentUrl.Attributes(
                    TestEnrollmentUrl.Extension([.. TestEnrollmentUrl.IA5String("https://host/dvls"), 0x05, 0x00]))),
            null),
    };
    // Each request breaks a rule of the CSR profile, and a request that breaks one gets invalid_request;
    // each row's markers name the rule it breaks.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Theory]
    [MemberData(nameof(InvalidRequestNames))]
    public void RejectsInvalidRequest(string request)
    {
        AssertInvalid(CertificateSigningRequest.Validate(InvalidRequests[request]()));
    }

    private static CertificateSigningRequest AssertValid(CsrValidationResult result)
    {
        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Null(result.Error);

        return result.Csr;
    }

    // CONTRACT.agent-identity.md §4: a CSR that breaks a rule gets invalid_request, which §5.4 maps to 400.
    private static void AssertInvalid(CsrValidationResult result)
    {
        Assert.False(result.Succeeded);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, result.Error.Code);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
        Assert.Equal(400, result.Error.HttpStatusCode);
        // oracle: mutant an empty failure detail for a CSR that is followed by other bytes,
        // that has a version other than 0, or whose key is not an id-ecPublicKey key
        Assert.False(string.IsNullOrEmpty(result.FailureDetail));
    }

    // The valid vector, checked to be accepted, so that only the rule a test breaks in it can reject the result.
    private static byte[] AcceptedValidVector()
    {
        byte[] valid = TestVectors.Instance.Csr["valid"].Csr;
        // oracle: reference docs/agent-identity/test-vectors.json csr.valid
        AssertValid(CertificateSigningRequest.Validate(valid));

        return valid;
    }

    // The contents of the valid vector's outer SEQUENCE, located by System.Formats.Asn1,
    // so that a test depends on no octet or length of the vector.
    private static byte[] ValidVectorContents()
    {
        byte[] valid = AcceptedValidVector();
        _ = AsnDecoder.ReadEncodedValue(valid, AsnEncodingRules.DER, out int offset, out int length, out _);
        byte[] contents = valid[offset..(offset + length)];

        // Wrapped again with the fewest length octets, the contents give back the vector,
        // so a test that wraps them otherwise changes only the form of the length.
        // oracle: spec X.690 §10.1
        Assert.Equal(valid, TestCsr.Sequence(contents));

        return contents;
    }

    private static ECDsa NewKey()
    {
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    private static ECDsa NewKeyWhere(Func<byte[], bool> pointCondition)
    {
        for (int attempt = 0; attempt < 64; attempt++)
        {
            ECDsa key = NewKey();
            if (pointCondition(TestCsr.UncompressedPoint(key)))
            {
                return key;
            }

            key.Dispose();
        }

        throw new InvalidOperationException("No key met the condition in 64 attempts.");
    }

    private static Func<byte[]> WithNewKey(Func<ECDsa, byte[]> request)
    {
        return () =>
        {
            using ECDsa key = NewKey();
            return request(key);
        };
    }

    private static byte[] RequestWithAttributes(ECDsa key, byte[] attributes)
    {
        byte[] info = TestCsr.Sequence(
            TestCsr.Integer(0),
            TestCsr.EmptySubject,
            key.ExportSubjectPublicKeyInfo(),
            attributes);

        return TestCsr.Request(info, key);
    }

    private static byte[] RequestWithKeyAlgorithm(ECDsa key, byte[] algorithm)
    {
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        return TestCsr.Request(TestCsr.RequestInfo(spki), key);
    }

    // A request for the uncompressed point of the given coordinates, after checking that the point is on P-256
    // once its coordinates are reduced modulo p.
    // The private key of such a point is unknown, and the key is invalid whatever the signature,
    // so r = s = 1 stands in for the signature.
    private static byte[] RequestWithPointOnP256ModuloP(string x, string y)
    {
        byte[] point = [0x04, .. Convert.FromHexString(x), .. Convert.FromHexString(y)];
        // oracle: spec SEC 2 §2.4.2
        Assert.True(IsOnP256ModuloP(point));

        return TestCsr.Sequence(
            TestCsr.RequestInfo(TestCsr.SubjectPublicKeyInfo(TestCsr.P256Algorithm(), point)),
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(TestCsr.Sequence(TestCsr.Integer(1), TestCsr.Integer(1))));
    }

    private static byte[] RequestWithPoint(ECDsa signer, byte[] point)
    {
        byte[] spki = TestCsr.SubjectPublicKeyInfo(TestCsr.P256Algorithm(), point);

        return TestCsr.Request(TestCsr.RequestInfo(spki), signer);
    }

    // The ECParameters of P-256 (RFC 3279 §2.3.5), which SEC 1 §C.2 calls SpecifiedECDomain,
    // written by hand because not every platform exports a named curve's explicit parameters.
    // Each value is that of secp256r1 in SEC 2 §2.4.2.
    private static byte[] P256SpecifiedDomain()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // version: ecpVer1.
            writer.WriteInteger(1);

            // fieldID: prime-field, { id-fieldType 1 } (RFC 3279 §2.3.5), whose parameters are the prime p.
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.10045.1.1");
                writer.WriteIntegerUnsigned(
                    Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
            }

            // curve: the coefficients a and b, each a field element of 32 octets (SEC 1 §2.3.5), and no seed.
            using (writer.PushSequence())
            {
                writer.WriteOctetString(
                    Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"));
                writer.WriteOctetString(
                    Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"));
            }

            // base: the base point G in uncompressed form (SEC 1 §2.3.3).
            writer.WriteOctetString(Convert.FromHexString(
                "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

            // order: n.
            writer.WriteIntegerUnsigned(
                Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));

            // cofactor: h.
            writer.WriteInteger(1);
        }

        return writer.Encode();
    }

    // Each attempt signs a request info with another subject, so that the search does not rely on random signatures.
    private static (byte[] Info, byte[] Signature) SignedInfoWhere(ECDsa key, Func<byte[], byte[], bool> condition)
    {
        for (int attempt = 0; attempt < 64; attempt++)
        {
            byte[] subject = new X500DistinguishedName($"CN=attempt {attempt}").RawData;
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject);
            byte[] signature = TestCsr.Sign(key, info);
            (byte[] r, byte[] s) = ReadSignature(signature);
            if (condition(r, s))
            {
                return (info, signature);
            }
        }

        throw new InvalidOperationException("No signature met the condition in 64 attempts.");
    }

    // The contents of the two INTEGERs of an ECDSA-Sig-Value.
    private static (byte[] R, byte[] S) ReadSignature(byte[] signature)
    {
        AsnReader sequence = new AsnReader(signature, AsnEncodingRules.DER).ReadSequence();

        return (sequence.ReadIntegerBytes().ToArray(), sequence.ReadIntegerBytes().ToArray());
    }

    // SEC 2 §2.4.2: whether the coordinates of an uncompressed point, reduced modulo p, satisfy y² = x³ - 3x + b.
    private static bool IsOnP256ModuloP(byte[] point)
    {
        BigInteger x = Unsigned(point[1..33]) % P256Prime;
        BigInteger y = Unsigned(point[33..]) % P256Prime;

        return BigInteger.ModPow(y, 2, P256Prime) == ((x * x * x) - (3 * x) + P256B) % P256Prime;
    }

    private static BigInteger Unsigned(byte[] bigEndian)
    {
        return new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true);
    }
}
