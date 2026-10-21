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
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
        ["empty attribute set"] = key =>
            TestCsr.Request(TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), attributes: [0xA0, 0x00]), key),

        // CONTRACT.agent-identity.md §4: the server ignores an extensionRequest with an empty Extensions list,
        // which common CSR builders emit although RFC 5280 §4.1 gives Extensions SIZE (1..MAX).
        // The attribute is the PKCS #9 extensionRequest (RFC 2985 §5.4.2) with one value, an empty SEQUENCE.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
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
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
        ["attributes out of DER order"] = key =>
        {
            static byte[] Attribute(string oid) =>
                TestCsr.Sequence(TestCsr.Oid(oid), TestCsr.Tlv(0x31, TestCsr.Tlv(0x0C, "a"u8.ToArray())));
            byte[] info = TestCsr.RequestInfo(
                key.ExportSubjectPublicKeyInfo(),
                attributes: TestCsr.Tlv(0xA0, Attribute("1.2.4"), Attribute("1.2.3")));
            return TestCsr.Request(info, key);
        },
    };

    // X.690 §10.1: DER writes each length in the fewest octets.
    private static readonly Dictionary<string, Func<byte[]>> RequestsWithALongerLength = new()
    {
        // The self-signature covers only the request info, so the request still verifies with a longer outer length.
        ["CertificationRequest"] = () => TestCsr.TlvWithLongerLength(0x30, ValidVectorContents()),

        // The same rule inside the request info, which a test can only change by signing the request again.
        ["subject"] = () =>
        {
            using ECDsa key = NewKey();
            byte[] subject = TestCsr.TlvWithLongerLength(0x30, []);
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject);
            return TestCsr.Request(info, key);
        },
    };

    // RFC 2986 §4 defines exactly the fields of each SEQUENCE, with no extension marker,
    // and RFC 5480 §2 those of SubjectPublicKeyInfo and of its AlgorithmIdentifier.
    private static readonly Dictionary<string, Func<ECDsa, byte[]>> RequestsWithAnExtraElement = new()
    {
        // oracle: spec RFC 2986 §4.1
        ["CertificationRequestInfo"] = key =>
        {
            byte[] info = TestCsr.Sequence(
                TestCsr.Integer(0),
                TestCsr.EmptySubject,
                key.ExportSubjectPublicKeyInfo(),
                TestCsr.EmptyAttributes,
                TestCsr.Null);
            return TestCsr.Request(info, key);
        },
        // oracle: spec RFC 2986 §4.2
        ["CertificationRequest"] = key =>
        {
            byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
            return TestCsr.Sequence(
                info,
                TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
                TestCsr.BitString(TestCsr.Sign(key, info)),
                TestCsr.Null);
        },

        // Another element would give the key a second SubjectPublicKeyInfo, and so a second SHA-256.
        // oracle: spec RFC 5480 §2
        ["AlgorithmIdentifier of the key"] = key =>
        {
            byte[] algorithm = TestCsr.Sequence(
                TestCsr.Oid(TestCsr.IdEcPublicKey),
                TestCsr.Oid(TestCsr.Secp256r1),
                TestCsr.Null);
            byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        },
        // oracle: spec RFC 5480 §2
        ["SubjectPublicKeyInfo"] = key =>
        {
            byte[] spki = TestCsr.Sequence(
                TestCsr.P256Algorithm(),
                TestCsr.BitString(TestCsr.UncompressedPoint(key)),
                TestCsr.Null);
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        },
    };

    private static readonly Dictionary<string, Func<byte[]>> RequestsForAKeyNotNamedP256 = new()
    {
        // The key is a P-256 key.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
        ["P-384 key"] = () =>
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            return TestCsr.For(key);
        },

        // secp256k1 (SEC 2 §2.4.1) points also take 65 octets uncompressed, so only the curve name tells them apart.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
        ["P-256 point named secp256k1"] = () =>
        {
            using ECDsa key = NewKey();
            byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), TestCsr.Oid("1.3.132.0.10"));
            byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        },
    };

    // RFC 5480 §2.1.1: the parameters of id-ecPublicKey MUST be present, and only namedCurve is allowed.
    private static readonly Dictionary<string, Func<ECDsa, byte[]>> KeysWithoutANamedCurve = new()
    {
        ["no parameters"] = key => TestCsr.SubjectPublicKeyInfo(
            TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey)),
            TestCsr.UncompressedPoint(key)),
        ["implicitCurve"] = key => TestCsr.SubjectPublicKeyInfo(
            TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), TestCsr.Null),
            TestCsr.UncompressedPoint(key)),

        // The specified form of the P-256 domain parameters,
        // which .NET writes for a key imported with explicit parameters.
        ["specifiedCurve"] = key =>
        {
            using ECDsa explicitKey = ECDsa.Create(key.ExportExplicitParameters(includePrivateParameters: false));
            return explicitKey.ExportSubjectPublicKeyInfo();
        },
    };

    // CONTRACT.agent-identity.md §4: an uncompressed point, so that each key has exactly one SubjectPublicKeyInfo.
    private static readonly Dictionary<string, Func<ECDsa, byte[]>> PointsNotUncompressed = new()
    {
        // The compressed form is 02 for an even y or 03 for an odd y, then x.
        // oracle: spec SEC 1 §2.3.3
        ["compressed"] = key =>
        {
            ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
            return [(byte)(0x02 | (parameters.Q.Y![^1] & 1)), .. parameters.Q.X!];
        },

        // ANSI X9.62 also defines a hybrid form, 06 or 07 then both coordinates; RFC 5480 §2.2 rejects it.
        // oracle: spec RFC 5480 §2.2
        ["hybrid"] = key =>
        {
            byte[] point = TestCsr.UncompressedPoint(key);
            point[0] = (byte)(0x06 | (point[^1] & 1));
            return point;
        },

        // The uncompressed form is 04, then x and y in 32 octets each, 65 octets in all.
        // oracle: spec SEC 1 §2.3.3
        ["without its form octet"] = key => TestCsr.UncompressedPoint(key)[1..],
        ["with an extra octet"] = key => [.. TestCsr.UncompressedPoint(key), 0x00],

        // The point at infinity is the single octet 00.
        // oracle: spec SEC 1 §2.3.3
        ["point at infinity"] = _ => [0x00],
    };

    // X.690 §11.2.1: DER requires an unused bit to be zero, so each BIT STRING is one whose last octet is even.
    private static readonly Dictionary<string, Func<byte[]>> RequestsWithUnusedBits = new()
    {
        // The octets of the point become the bits of the BIT STRING, so none is unused.
        // oracle: spec RFC 5480 §2.2
        ["subjectPublicKey"] = () =>
        {
            using ECDsa key = NewKeyWhere(point => (point[^1] & 1) == 0);
            byte[] spki = TestCsr.SubjectPublicKeyInfo(
                TestCsr.P256Algorithm(),
                TestCsr.UncompressedPoint(key),
                unusedBits: 1);
            return TestCsr.Request(TestCsr.RequestInfo(spki), key);
        },

        // The BIT STRING holds the octets of the DER Ecdsa-Sig-Value, so none is unused.
        // oracle: spec RFC 3279 §2.2
        // oracle: spec RFC 3279 §2.2.3
        ["signature"] = () =>
        {
            using ECDsa key = NewKey();
            (byte[] info, byte[] signature) = SignedInfoWhere(key, (_, s) => (s[^1] & 1) == 0);
            return TestCsr.Sequence(
                info,
                TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
                TestCsr.BitString(signature, unusedBits: 1));
        },
    };

    // Uncompressed points with a coordinate of p or more, each another encoding of a point on P-256,
    // which would give its key a second SubjectPublicKeyInfo SHA-256.
    private static readonly Dictionary<string, (string X, string Y)> PointsWithACoordinateOutOfTheField = new()
    {
        // x = p, which is 0 modulo p, and y a square root of b modulo p.
        ["x"] = (
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "66485C780E2F83D72433BD5D84A06BB6541C2AF31DAE871728BF856A174F93F4"),

        // y = p + 1, which is 1 modulo p, and x a root of x³ - 3x + b - 1 modulo p.
        ["y"] = (
            "09E78D4EF60D05F750F6636209092BC43CBDD6B47E11A9DE20A9FEB2A50BB96C",
            "FFFFFFFF00000001000000000000000000000001000000000000000000000000"),
    };

    public static TheoryData<string> RequestWithIgnoredContentsNames => new(RequestsWithIgnoredContents.Keys);

    public static TheoryData<string> RequestWithALongerLengthNames => new(RequestsWithALongerLength.Keys);

    public static TheoryData<string> RequestWithAnExtraElementNames => new(RequestsWithAnExtraElement.Keys);

    public static TheoryData<string> RequestForAKeyNotNamedP256Names => new(RequestsForAKeyNotNamedP256.Keys);

    public static TheoryData<string> KeyWithoutANamedCurveNames => new(KeysWithoutANamedCurve.Keys);

    public static TheoryData<string> PointNotUncompressedNames => new(PointsNotUncompressed.Keys);

    public static TheoryData<string> RequestWithUnusedBitsNames => new(RequestsWithUnusedBits.Keys);

    public static TheoryData<string> PointWithACoordinateOutOfTheFieldNames =>
        new(PointsWithACoordinateOutOfTheField.Keys);

    // test-vectors.json csr.<name>.expected, the outcome CONTRACT.agent-identity.md §4 gives each request.
    // oracle: reference docs/agent-identity/test-vectors.json csr
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
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
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §2.1
        Assert.Equal(SHA256.HashData(expected), csr.SubjectPublicKeyInfoSha256.ToArray());
    }

    // A request written by .NET rather than by the test builder.
    // A P-256 key and ecdsa-with-SHA256, the profile .NET writes for this key.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Fact]
    public void AcceptsRequestWrittenByDotNet()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] der = new CertificateRequest("CN=ignored", key, HashAlgorithmName.SHA256).CreateSigningRequest();

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(der));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Theory]
    [MemberData(nameof(RequestWithIgnoredContentsNames))]
    public void AcceptsAnySubjectAndAttributes(string request)
    {
        using ECDsa key = NewKey();

        CertificateSigningRequest csr =
            AssertValid(CertificateSigningRequest.Validate(RequestsWithIgnoredContents[request](key)));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // None of these is a CertificationRequest.
    // oracle: spec RFC 2986 §4
    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("3000")]
    [InlineData("300330010A")]
    public void RejectsBytesThatAreNotARequest(string hex)
    {
        AssertInvalid(CertificateSigningRequest.Validate(Convert.FromHexString(hex)));
    }

    // A CSR is DER, the encoding of one request.
    // Bytes after the request would give one request many encodings.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [Fact]
    public void RejectsTrailingBytes()
    {
        byte[] valid = AcceptedValidVector();

        AssertInvalid(CertificateSigningRequest.Validate([.. valid, 0x00]));
    }

    // oracle: spec X.690 §10.1
    [Theory]
    [MemberData(nameof(RequestWithALongerLengthNames))]
    public void RejectsLengthInMoreOctetsThanNeeded(string element)
    {
        AssertInvalid(CertificateSigningRequest.Validate(RequestsWithALongerLength[element]()));
    }

    // DER uses the definite form of length.
    // oracle: spec X.690 §10.1
    [Fact]
    public void RejectsIndefiniteLength()
    {
        byte[] contents = ValidVectorContents();

        AssertInvalid(CertificateSigningRequest.Validate([0x30, 0x80, .. contents, 0x00, 0x00]));
    }

    // version is v1, encoded 0.
    // oracle: spec RFC 2986 §4.1
    [Fact]
    public void RejectsVersion1()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.Sequence(
            TestCsr.Integer(1),
            TestCsr.EmptySubject,
            key.ExportSubjectPublicKeyInfo(),
            TestCsr.EmptyAttributes);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    // The subject is a Name, which is a SEQUENCE.
    // oracle: spec RFC 2986 §4.1
    // oracle: spec RFC 5280 §4.1.2.4
    [Fact]
    public void RejectsSubjectThatIsNotASequence()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject: [0x31, 0x00]);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    // attributes is a required field, a constructed [0] IMPLICIT SET OF Attribute.
    // The rows leave it out and write it primitive, 80 00.
    // oracle: spec RFC 2986 §4.1
    [Theory]
    [InlineData("")]
    // The module of Appendix A uses IMPLICIT TAGS, and X.690 8.14.4 a) keeps an implicitly tagged SET OF constructed.
    // oracle: spec RFC 2986 §A
    // oracle: spec X.690 §8.14
    [InlineData("8000")]
    public void RejectsRequestInfoWithoutConstructedAttributes(string attributes)
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.Sequence(
            TestCsr.Integer(0),
            TestCsr.EmptySubject,
            key.ExportSubjectPublicKeyInfo(),
            Convert.FromHexString(attributes));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    [Theory]
    [MemberData(nameof(RequestWithAnExtraElementNames))]
    public void RejectsExtraElement(string sequence)
    {
        using ECDsa key = NewKey();

        AssertInvalid(CertificateSigningRequest.Validate(RequestsWithAnExtraElement[sequence](key)));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Theory]
    [MemberData(nameof(RequestForAKeyNotNamedP256Names))]
    public void RejectsKeyNotNamedP256(string key)
    {
        AssertInvalid(CertificateSigningRequest.Validate(RequestsForAKeyNotNamedP256[key]()));
    }

    // RFC 5480 §2.1.2: id-ecDH restricts the key to key agreement; CONTRACT.agent-identity.md §4 needs a signing key.
    // oracle: spec RFC 5480 §2.1.2
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Fact]
    public void RejectsKeyRestrictedToKeyAgreement()
    {
        using ECDsa key = NewKey();
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid("1.3.132.1.12"), TestCsr.Oid(TestCsr.Secp256r1));
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // oracle: spec RFC 5480 §2.1.1
    [Theory]
    [MemberData(nameof(KeyWithoutANamedCurveNames))]
    public void RejectsKeyWithoutANamedCurve(string parameters)
    {
        using ECDsa key = NewKey();
        byte[] spki = KeysWithoutANamedCurve[parameters](key);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Theory]
    [MemberData(nameof(PointNotUncompressedNames))]
    public void RejectsPointNotUncompressed(string point)
    {
        using ECDsa key = NewKey();

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, PointsNotUncompressed[point](key))));
    }

    // The key is a point on P-256.
    // Flipping the low bit of y leaves the point off the curve,
    // since the only other point with the same x has y' = p - y, which is y + 1 or y - 1 only for y = (p ± 1) / 2.
    // No private key exists for such a point, so the key whose point was altered signs the request.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Fact]
    public void RejectsPointOffTheCurve()
    {
        using ECDsa key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(TestVectors.Instance.Key("device-a").PrivateKeyPkcs8, out _);
        byte[] point = TestCsr.UncompressedPoint(key);
        point[^1] ^= 0x01;

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, point)));
    }

    // SEC 1 §3.2.2.1: the coordinates of a public key are integers below p,
    // and CONTRACT.agent-identity.md §4 gives a key that is not a P-256 point invalid_request, not an exception.
    // Each point is on the curve modulo p, so only the range of its coordinates rejects it;
    // a platform's key import throws an exception of a platform-specific type for such a point.
    // The private key of either point is unknown, and the key is invalid whatever the signature,
    // so r = s = 1 stands in for the signature.
    // oracle: spec SEC 1 §3.2.2.1
    [Theory]
    [MemberData(nameof(PointWithACoordinateOutOfTheFieldNames))]
    public void RejectsPointWithACoordinateOutOfTheField(string coordinate)
    {
        (string x, string y) = PointsWithACoordinateOutOfTheField[coordinate];
        byte[] point = [0x04, .. Convert.FromHexString(x), .. Convert.FromHexString(y)];
        // oracle: spec SEC 2 §2.4.2
        Assert.True(IsOnP256ModuloP(point));
        byte[] der = TestCsr.Sequence(
            TestCsr.RequestInfo(TestCsr.SubjectPublicKeyInfo(TestCsr.P256Algorithm(), point)),
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(TestCsr.Sequence(TestCsr.Integer(1), TestCsr.Integer(1))));

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    [Theory]
    [MemberData(nameof(RequestWithUnusedBitsNames))]
    public void RejectsBitStringWithUnusedBits(string bitString)
    {
        AssertInvalid(CertificateSigningRequest.Validate(RequestsWithUnusedBits[bitString]()));
    }

    // The signature algorithm is ecdsa-with-SHA256, even when the signature verifies under it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Fact]
    public void RejectsAnotherSignatureAlgorithmOverASha256Signature()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
        byte[] algorithm = TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha384);
        byte[] der = TestCsr.Request(info, key, algorithm, HashAlgorithmName.SHA256);

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    // The AlgorithmIdentifier of ecdsa-with-SHA256 MUST omit the parameters.
    // oracle: spec RFC 5758 §3.2
    [Fact]
    public void RejectsSignatureAlgorithmWithNullParameters()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.EcdsaWithSha256), TestCsr.Null);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key, algorithm)));
    }

    // Security invariant 1: the self-signature is the proof of possession of the request's key.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
    [Fact]
    public void RejectsRequestSignedByAnotherKey()
    {
        using ECDsa key = NewKey();
        using ECDsa other = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, other)));
    }

    // The signature is a DER ECDSA-Sig-Value, not the 64-octet r‖s form that request signatures use.
    // oracle: spec RFC 5758 §3.2
    // oracle: spec RFC 3279 §2.2.3
    [Fact]
    public void RejectsSignatureInFixedFieldForm()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
        byte[] signature = key.SignData(
            info,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        byte[] der = TestCsr.Sequence(
            info,
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(signature));

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    // SEC 1 4.1.4 step 1: a verifier outputs "invalid" unless r and s are both in [1, n - 1], so both are positive.
    // An r whose top bit is set needs a leading zero octet; without it, DER reads a negative number,
    // which the BCL verifier accepts as the unsigned value, so only the library's own check rejects it.
    // An r that would start FF after the zero octet is skipped, since its negative form would not be minimal DER.
    // oracle: spec SEC 1 §4.1.4
    // oracle: spec X.690 §8.3
    [Fact]
    public void RejectsSignatureWithNegativeR()
    {
        using ECDsa key = NewKey();
        (byte[] info, byte[] signature) = SignedInfoWhere(key, (r, _) => r.Length == 33 && r[1] != 0xFF);
        (byte[] r, byte[] s) = ReadSignature(signature);
        byte[] negative = TestCsr.Sequence(TestCsr.Tlv(0x02, r[1..]), TestCsr.Tlv(0x02, s));
        // oracle: reference .NET ECDsa.VerifyData
        Assert.True(key.VerifyData(info, negative, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        byte[] der = TestCsr.Sequence(
            info,
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(negative));

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    private static CertificateSigningRequest AssertValid(CsrValidationResult result)
    {
        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Null(result.Error);
        // oracle: scaffold
        Assert.Null(result.FailureDetail);

        return result.Csr;
    }

    // CONTRACT.agent-identity.md §4: a CSR that breaks a rule gets invalid_request, which §5.4 maps to 400.
    private static void AssertInvalid(CsrValidationResult result)
    {
        Assert.False(result.Succeeded);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §4
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, result.Error.Code);
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-errors
        Assert.Equal(400, result.Error.HttpStatusCode);
        // oracle: mutant an empty failure detail for a CSR that is followed by other bytes,
        // that has a version other than 0, or whose key is not an id-ecPublicKey key
        Assert.False(string.IsNullOrEmpty(result.FailureDetail));
        // oracle: scaffold
        Assert.Null(result.Csr);
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

    private static byte[] RequestWithPoint(ECDsa signer, byte[] point)
    {
        byte[] spki = TestCsr.SubjectPublicKeyInfo(TestCsr.P256Algorithm(), point);

        return TestCsr.Request(TestCsr.RequestInfo(spki), signer);
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
