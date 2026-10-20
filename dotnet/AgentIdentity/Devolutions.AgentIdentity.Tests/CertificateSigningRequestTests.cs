using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity.Tests;

public class CertificateSigningRequestTests
{
    // RFC 5480 §2: the DER SubjectPublicKeyInfo of a P-256 key up to its uncompressed point,
    // SEQUENCE { SEQUENCE { id-ecPublicKey, secp256r1 }, BIT STRING of 66 octets with no unused bits }.
    internal static readonly byte[] P256SubjectPublicKeyInfoPrefix =
        Convert.FromHexString("3059301306072A8648CE3D020106082A8648CE3D030107034200");

    [Theory]
    [MemberData(nameof(VectorData.CsrNames), MemberType = typeof(VectorData))]
    public void CsrVectorHasItsExpectedOutcome(string name)
    {
        CsrVector vector = TestVectors.Instance.Csr[name];

        CsrValidationResult result = CertificateSigningRequest.Validate(vector.Csr);

        Assert.Equal(vector.Expected, result.Succeeded ? "ok" : result.Error.Code.ToWireValue());
    }

    [Fact]
    public void ValidVectorYieldsTheSubjectPublicKeyInfoOfItsKey()
    {
        CsrVector vector = TestVectors.Instance.Csr["valid"];
        Assert.NotNull(vector.PublicKeySec1);
        byte[] expected = [.. P256SubjectPublicKeyInfoPrefix, .. vector.PublicKeySec1];

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(vector.Csr));

        Assert.Equal(expected, csr.SubjectPublicKeyInfo.ToArray());
        Assert.Equal(SHA256.HashData(expected), csr.SubjectPublicKeyInfoSha256.ToArray());
    }

    // A request written by .NET rather than by the test builder.
    [Fact]
    public void AcceptsRequestWrittenByDotNet()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] der = new CertificateRequest("CN=ignored", key, HashAlgorithmName.SHA256).CreateSigningRequest();

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(der));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // CONTRACT.md §4: the server ignores the CSR's subject and attributes, including requested extensions,
    // and security invariant 2 lets a CSR supply only a verified public key.
    [Fact]
    public void AcceptsAnySubjectAttributesAndExtensions()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=Administrator, O=Another Identity", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        SubjectAlternativeNameBuilder alternativeName = new();
        alternativeName.AddUri(new Uri("urn:uuid:5d2e8f14-3c61-4b7a-8e29-6a0f4c1d7b02"));
        request.CertificateExtensions.Add(alternativeName.Build());
        // RFC 2985 §5.4.1 challengePassword, a DirectoryString.
        byte[] challengePassword = [0x0C, 0x02, 0x70, 0x77];
        request.OtherRequestAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.7", challengePassword));

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(request.CreateSigningRequest()));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // CONTRACT.md §4: the agent's CSR carries an empty attribute set, A0 00.
    [Fact]
    public void AcceptsEmptyAttributeSet()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), attributes: [0xA0, 0x00]);

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    // CONTRACT.md §4: the server ignores an extensionRequest with an empty Extensions list,
    // which common CSR builders emit although RFC 5280 §4.1 gives Extensions SIZE (1..MAX).
    // The attribute is the PKCS #9 extensionRequest (RFC 2985 §5.4.2) with one value, an empty SEQUENCE.
    [Fact]
    public void AcceptsExtensionRequestWithEmptyExtensions()
    {
        using ECDsa key = NewKey();
        byte[] extensionRequest = TestCsr.Sequence(
            TestCsr.Oid("1.2.840.113549.1.9.14"),
            TestCsr.Tlv(0x31, TestCsr.Sequence()));
        byte[] info = TestCsr.RequestInfo(
            key.ExportSubjectPublicKeyInfo(),
            attributes: TestCsr.Tlv(0xA0, extensionRequest));

        CertificateSigningRequest csr = AssertValid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));

        Assert.Equal(key.ExportSubjectPublicKeyInfo(), csr.SubjectPublicKeyInfo.ToArray());
    }

    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("3000")]
    [InlineData("300330010A")]
    public void RejectsBytesThatAreNotARequest(string hex)
    {
        AssertInvalid(CertificateSigningRequest.Validate(Convert.FromHexString(hex)));
    }

    // Bytes after the request would give one request many encodings.
    [Fact]
    public void RejectsTrailingBytes()
    {
        byte[] valid = AcceptedValidVector();

        AssertInvalid(CertificateSigningRequest.Validate([.. valid, 0x00]));
    }

    // X.690 §10.1: DER writes each length in the fewest octets.
    // The self-signature covers only the request info, so the request still verifies with a longer outer length.
    [Fact]
    public void RejectsLengthInMoreOctetsThanNeeded()
    {
        byte[] contents = ValidVectorContents();

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.TlvWithLongerLength(0x30, contents)));
    }

    // X.690 §10.1: DER uses the definite form of length.
    [Fact]
    public void RejectsIndefiniteLength()
    {
        byte[] contents = ValidVectorContents();

        AssertInvalid(CertificateSigningRequest.Validate([0x30, 0x80, .. contents, 0x00, 0x00]));
    }

    // The same rule inside the request info, which a test can only change by signing the request again.
    [Fact]
    public void RejectsLengthInMoreOctetsThanNeededInsideTheRequestInfo()
    {
        using ECDsa key = NewKey();
        byte[] subject = TestCsr.TlvWithLongerLength(0x30, []);
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    // RFC 2986 §4.1: version is v1, encoded 0.
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

    // RFC 2986 §4.1: the subject is a Name, which is a SEQUENCE.
    [Fact]
    public void RejectsSubjectThatIsNotASequence()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo(), subject: [0x31, 0x00]);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    // RFC 2986 §4.1: attributes is a required field, a constructed [0] IMPLICIT SET OF Attribute.
    [Fact]
    public void RejectsRequestInfoWithoutAttributes()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.Sequence(TestCsr.Integer(0), TestCsr.EmptySubject, key.ExportSubjectPublicKeyInfo());

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    [Fact]
    public void RejectsPrimitiveAttributes()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.Sequence(
            TestCsr.Integer(0),
            TestCsr.EmptySubject,
            key.ExportSubjectPublicKeyInfo(),
            [0x80, 0x00]);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    // RFC 2986 §4 defines exactly the fields of each SEQUENCE, with no extension marker.
    [Fact]
    public void RejectsExtraElementInRequestInfo()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.Sequence(
            TestCsr.Integer(0),
            TestCsr.EmptySubject,
            key.ExportSubjectPublicKeyInfo(),
            TestCsr.EmptyAttributes,
            TestCsr.Null);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key)));
    }

    [Fact]
    public void RejectsExtraElementInRequest()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
        byte[] der = TestCsr.Sequence(
            info,
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(TestCsr.Sign(key, info)),
            TestCsr.Null);

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    // CONTRACT.md §4: the key is a P-256 key.
    [Fact]
    public void RejectsKeyOnAnotherCurve()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.For(key)));
    }

    // secp256k1 (SEC 2 §2.4.1) points also take 65 octets uncompressed, so only the curve name tells them apart.
    [Fact]
    public void RejectsP256PointNamedAsAnotherCurve()
    {
        using ECDsa key = NewKey();
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), TestCsr.Oid("1.3.132.0.10"));
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // Another element would give the key a second SubjectPublicKeyInfo, and so a second SHA-256.
    [Fact]
    public void RejectsKeyAlgorithmWithAnExtraElement()
    {
        using ECDsa key = NewKey();
        byte[] algorithm = TestCsr.Sequence(
            TestCsr.Oid(TestCsr.IdEcPublicKey),
            TestCsr.Oid(TestCsr.Secp256r1),
            TestCsr.Null);
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    [Fact]
    public void RejectsSubjectPublicKeyInfoWithAnExtraElement()
    {
        using ECDsa key = NewKey();
        byte[] spki = TestCsr.Sequence(
            TestCsr.P256Algorithm(),
            TestCsr.BitString(TestCsr.UncompressedPoint(key)),
            TestCsr.Null);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // RFC 5480 §2.1.2: id-ecDH restricts the key to key agreement; CONTRACT.md §4 needs a signing key.
    [Fact]
    public void RejectsKeyRestrictedToKeyAgreement()
    {
        using ECDsa key = NewKey();
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid("1.3.132.1.12"), TestCsr.Oid(TestCsr.Secp256r1));
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // RFC 5480 §2.1.1: the parameters of id-ecPublicKey MUST be present, and only namedCurve is allowed.
    [Fact]
    public void RejectsKeyWithoutCurveParameters()
    {
        using ECDsa key = NewKey();
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey));
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    [Fact]
    public void RejectsImplicitCurve()
    {
        using ECDsa key = NewKey();
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.IdEcPublicKey), TestCsr.Null);
        byte[] spki = TestCsr.SubjectPublicKeyInfo(algorithm, TestCsr.UncompressedPoint(key));

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // The specified form of the P-256 domain parameters, which .NET writes for a key imported with explicit parameters.
    [Fact]
    public void RejectsSpecifiedCurve()
    {
        using ECDsa key = NewKey();
        using ECDsa explicitKey = ECDsa.Create(key.ExportExplicitParameters(includePrivateParameters: false));
        byte[] spki = explicitKey.ExportSubjectPublicKeyInfo();

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // CONTRACT.md §4: an uncompressed point, so that each key has exactly one SubjectPublicKeyInfo.
    // SEC 1 §2.3.3: the compressed form is 02 for an even y or 03 for an odd y, then x.
    [Fact]
    public void RejectsCompressedPoint()
    {
        using ECDsa key = NewKey();
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        byte[] point = [(byte)(0x02 | (parameters.Q.Y![^1] & 1)), .. parameters.Q.X!];

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, point)));
    }

    // ANSI X9.62 also defines a hybrid form, 06 or 07 then both coordinates; RFC 5480 §2.2 rejects it.
    [Fact]
    public void RejectsHybridPoint()
    {
        using ECDsa key = NewKey();
        byte[] point = TestCsr.UncompressedPoint(key);
        point[0] = (byte)(0x06 | (point[^1] & 1));

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, point)));
    }

    [Fact]
    public void RejectsPointWithoutItsFormOctet()
    {
        using ECDsa key = NewKey();

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, TestCsr.UncompressedPoint(key)[1..])));
    }

    [Fact]
    public void RejectsPointWithAnExtraOctet()
    {
        using ECDsa key = NewKey();
        byte[] point = [.. TestCsr.UncompressedPoint(key), 0x00];

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, point)));
    }

    // SEC 1 §2.3.3: the point at infinity is the single octet 00.
    [Fact]
    public void RejectsPointAtInfinity()
    {
        using ECDsa key = NewKey();

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, [0x00])));
    }

    // Flipping the low bit of y leaves the point off the curve,
    // since the only other point with the same x has y' = p - y, which is y + 1 or y - 1 only for y = (p ± 1) / 2.
    // No private key exists for such a point, so the key whose point was altered signs the request.
    [Fact]
    public void RejectsPointOffTheCurve()
    {
        using ECDsa key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(TestVectors.Instance.Key("device-a").PrivateKeyPkcs8, out _);
        byte[] point = TestCsr.UncompressedPoint(key);
        point[^1] ^= 0x01;

        AssertInvalid(CertificateSigningRequest.Validate(RequestWithPoint(key, point)));
    }

    // RFC 5480 §2.2: the octets of the point become the bits of the BIT STRING, so none is unused.
    // DER requires an unused bit to be zero, so the key is one whose last octet is even.
    [Fact]
    public void RejectsKeyBitStringWithUnusedBits()
    {
        using ECDsa key = NewKeyWhere(point => (point[^1] & 1) == 0);
        byte[] spki = TestCsr.SubjectPublicKeyInfo(
            TestCsr.P256Algorithm(),
            TestCsr.UncompressedPoint(key),
            unusedBits: 1);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(TestCsr.RequestInfo(spki), key)));
    }

    // CONTRACT.md §4: the signature algorithm is ecdsa-with-SHA256, even when the signature verifies under it.
    [Fact]
    public void RejectsAnotherSignatureAlgorithmOverASha256Signature()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
        byte[] algorithm = TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha384);
        byte[] der = TestCsr.Request(info, key, algorithm, HashAlgorithmName.SHA256);

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    // RFC 5758 §3.2: the AlgorithmIdentifier of ecdsa-with-SHA256 MUST omit the parameters.
    [Fact]
    public void RejectsSignatureAlgorithmWithNullParameters()
    {
        using ECDsa key = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());
        byte[] algorithm = TestCsr.Sequence(TestCsr.Oid(TestCsr.EcdsaWithSha256), TestCsr.Null);

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, key, algorithm)));
    }

    // Security invariant 1: the self-signature is the proof of possession of the request's key.
    [Fact]
    public void RejectsRequestSignedByAnotherKey()
    {
        using ECDsa key = NewKey();
        using ECDsa other = NewKey();
        byte[] info = TestCsr.RequestInfo(key.ExportSubjectPublicKeyInfo());

        AssertInvalid(CertificateSigningRequest.Validate(TestCsr.Request(info, other)));
    }

    // RFC 5758 §3.2: the signature is a DER ECDSA-Sig-Value, not the 64-octet r‖s form that request signatures use.
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

    // RFC 3279 §2.2.3: r and s are positive INTEGERs.
    // An r whose top bit is set needs a leading zero octet; without it, DER reads a negative number,
    // which the BCL verifier accepts as the unsigned value, so only the library's own check rejects it.
    // An r that would start FF after the zero octet is skipped, since its negative form would not be minimal DER.
    [Fact]
    public void RejectsSignatureWithNegativeR()
    {
        using ECDsa key = NewKey();
        (byte[] info, byte[] signature) = SignedInfoWhere(key, (r, _) => r.Length == 33 && r[1] != 0xFF);
        (byte[] r, byte[] s) = ReadSignature(signature);
        byte[] negative = TestCsr.Sequence(TestCsr.Tlv(0x02, r[1..]), TestCsr.Tlv(0x02, s));
        Assert.True(key.VerifyData(info, negative, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        byte[] der = TestCsr.Sequence(
            info,
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(negative));

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    // DER requires an unused bit to be zero, so the signature is one whose last octet is even.
    [Fact]
    public void RejectsSignatureBitStringWithUnusedBits()
    {
        using ECDsa key = NewKey();
        (byte[] info, byte[] signature) = SignedInfoWhere(key, (_, s) => (s[^1] & 1) == 0);
        byte[] der = TestCsr.Sequence(
            info,
            TestCsr.SignatureAlgorithm(TestCsr.EcdsaWithSha256),
            TestCsr.BitString(signature, unusedBits: 1));

        AssertInvalid(CertificateSigningRequest.Validate(der));
    }

    private static CertificateSigningRequest AssertValid(CsrValidationResult result)
    {
        Assert.True(result.Succeeded, result.FailureDetail);
        Assert.Null(result.Error);
        Assert.Null(result.FailureDetail);

        return result.Csr;
    }

    private static void AssertInvalid(CsrValidationResult result)
    {
        Assert.False(result.Succeeded);
        Assert.Equal(AgentIdentityErrorCode.InvalidRequest, result.Error.Code);
        Assert.Equal(400, result.Error.HttpStatusCode);
        Assert.False(string.IsNullOrEmpty(result.FailureDetail));
        Assert.Null(result.Csr);
    }

    // The valid vector, checked to be accepted, so that only the rule a test breaks in it can reject the result.
    private static byte[] AcceptedValidVector()
    {
        byte[] valid = TestVectors.Instance.Csr["valid"].Csr;
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
}
