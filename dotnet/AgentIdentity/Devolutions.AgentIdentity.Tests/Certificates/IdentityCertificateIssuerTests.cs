using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity.Tests;

// Each test decodes the issued certificate with the BCL and System.Formats.Asn1, never with the library,
// and checks it against CONTRACT.agent-identity.md §4 and RFC 5280.
public sealed class IdentityCertificateIssuerTests : IDisposable
{
    // CONTRACT.agent-identity.md §1: IDs are lowercase hyphenated UUIDs; this one has hexadecimal letters,
    // so its case shows.
    private const string IdentityIdText = "0b3c6a52-7a38-4f55-9a1c-2f1a8d3c9e01";

    // RFC 5280 §4.2.1.12: id-kp-clientAuth.
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";

    private const string SubjectKeyIdentifierOid = "2.5.29.14";
    private const string KeyUsageOid = "2.5.29.15";
    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";
    private const string ExtendedKeyUsageOid = "2.5.29.37";

    private static readonly Guid IdentityId = Guid.Parse(IdentityIdText.ToUpperInvariant());

    // 12:00:00.750 UTC, whose fraction a certificate cannot hold.
    private static readonly DateTimeOffset NowInSeconds = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = NowInSeconds.AddMilliseconds(750);

    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(30);

    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly RandomNumberGenerator _random = RandomNumberGenerator.Create();
    private readonly X509Certificate2 _root;
    private readonly CertificateSigningRequest _csr;

    public IdentityCertificateIssuerTests()
    {
        _root = CreateRoot(Now.AddDays(-1), Now.AddYears(10));

        byte[] csr = new CertificateRequest("CN=agent", _agentKey, HashAlgorithmName.SHA256).CreateSigningRequest();
        _csr = CertificateSigningRequest.Validate(csr).Csr!;
    }

    public void Dispose()
    {
        _root.Dispose();
        _rootKey.Dispose();
        _agentKey.Dispose();
        _random.Dispose();
    }

    // CONTRACT.agent-identity.md §4: the certificate is for the P-256 key of the CSR.
    [Fact]
    public void CertifiesTheKeyOfTheCsr()
    {
        using X509Certificate2 leaf = Issue();

        Assert.Equal(_agentKey.ExportSubjectPublicKeyInfo(), leaf.PublicKey.ExportSubjectPublicKeyInfo());
    }

    // CONTRACT.agent-identity.md §4: CN=<identity_id>, and the root's subject as the issuer.
    [Fact]
    public void SubjectIsTheCommonNameOfTheIdentity()
    {
        using X509Certificate2 leaf = Issue();

        X500RelativeDistinguishedName name = Assert.Single(leaf.SubjectName.EnumerateRelativeDistinguishedNames());
        Assert.Equal("2.5.4.3", name.GetSingleElementType().Value);
        Assert.Equal(IdentityIdText, name.GetSingleElementValue());
        Assert.Equal(_root.SubjectName.RawData, leaf.IssuerName.RawData);
    }

    // CONTRACT.agent-identity.md §4: SAN URI urn:uuid:<identity_id>.
    // RFC 5280 §4.2.1.6: GeneralNames is a SEQUENCE OF GeneralName, and a URI is [6] IA5String;
    // with a subject present, the extension is not critical.
    [Fact]
    public void AlternativeNameIsTheUrnUuidOfTheIdentity()
    {
        using X509Certificate2 leaf = Issue();
        X509Extension extension =
            Assert.IsType<X509Extension>(leaf.Extensions[SubjectAlternativeNameOid], exactMatch: false);

        AsnReader names = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
        string uri = names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));

        Assert.Equal($"urn:uuid:{IdentityIdText}", uri);
        Assert.False(names.HasData);
        Assert.False(extension.Critical);
    }

    // CONTRACT.agent-identity.md §4: EKU clientAuth.
    [Fact]
    public void ExtendedKeyUsageIsClientAuthenticationOnly()
    {
        using X509Certificate2 leaf = Issue();
        X509EnhancedKeyUsageExtension extension =
            Assert.IsType<X509EnhancedKeyUsageExtension>(leaf.Extensions[ExtendedKeyUsageOid]);

        Assert.Equal([ClientAuth], extension.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value));
        Assert.False(extension.Critical);
    }

    // CONTRACT.agent-identity.md §4: KeyUsage digitalSignature; RFC 5280 §4.2.1.3: marked critical.
    [Fact]
    public void KeyUsageIsCriticalDigitalSignatureOnly()
    {
        using X509Certificate2 leaf = Issue();
        X509KeyUsageExtension extension = Assert.IsType<X509KeyUsageExtension>(leaf.Extensions[KeyUsageOid]);

        Assert.Equal(X509KeyUsageFlags.DigitalSignature, extension.KeyUsages);
        Assert.True(extension.Critical);
    }

    // RFC 5280 §4.2.1.1: the key identifier of the issuer's subject key identifier, in a non-critical extension.
    [Fact]
    public void AuthorityKeyIdentifierIsTheSubjectKeyIdentifierOfTheIssuer()
    {
        using X509Certificate2 leaf = Issue();
        X509AuthorityKeyIdentifierExtension authority =
            Assert.IsType<X509AuthorityKeyIdentifierExtension>(leaf.Extensions[AuthorityKeyIdentifierOid]);
        X509SubjectKeyIdentifierExtension issuer =
            Assert.IsType<X509SubjectKeyIdentifierExtension>(_root.Extensions[SubjectKeyIdentifierOid]);

        Assert.Equal(issuer.SubjectKeyIdentifierBytes.ToArray(), authority.KeyIdentifier?.ToArray());
        Assert.Null(authority.NamedIssuer);
        Assert.Null(authority.SerialNumber);
        Assert.False(authority.Critical);
    }

    // RFC 5280 §4.2.1.2, method (1): the SHA-1 hash of the BIT STRING subjectPublicKey, in a non-critical extension.
    [Fact]
    public void SubjectKeyIdentifierIsTheSha1OfTheKey()
    {
        using X509Certificate2 leaf = Issue();
        X509SubjectKeyIdentifierExtension extension =
            Assert.IsType<X509SubjectKeyIdentifierExtension>(leaf.Extensions[SubjectKeyIdentifierOid]);

        byte[] subjectPublicKey = TestCsr.UncompressedPoint(_agentKey);

        Assert.Equal(SHA1.HashData(subjectPublicKey), extension.SubjectKeyIdentifierBytes.ToArray());
        Assert.False(extension.Critical);
    }

    // RFC 5280 §4.2.1.9: an end-entity certificate may omit basic constraints, and this profile does.
    [Fact]
    public void HasExactlyTheProfileExtensions()
    {
        using X509Certificate2 leaf = Issue();

        IEnumerable<string?> extensions = leaf.Extensions.Select(extension => extension.Oid?.Value);
        string[] expected =
        [
            SubjectKeyIdentifierOid,
            KeyUsageOid,
            SubjectAlternativeNameOid,
            AuthorityKeyIdentifierOid,
            ExtendedKeyUsageOid,
        ];

        Assert.Equal(expected, extensions.Order(StringComparer.Ordinal));
        Assert.Equal(3, leaf.Version);
    }

    // RFC 5758 §3.2: the issuer's generator signs with SHA-256, so ecdsa-with-SHA256 for a P-256 root.
    [Fact]
    public void IsSignedWithSha256()
    {
        using X509Certificate2 leaf = Issue();

        Assert.Equal("1.2.840.10045.4.3.2", leaf.SignatureAlgorithm.Value);
    }

    // RFC 5280 §4.1.2.2: a positive INTEGER of at most 20 octets.
    // The serial number is 16 octets from the injected generator with the top bit cleared.
    [Fact]
    public void SerialNumberIsTheRandomOctetsWithTheTopBitCleared()
    {
        byte[] draw = [.. Enumerable.Repeat((byte)0xFF, 16)];

        using X509Certificate2 leaf = Issue(random: new SequenceRandomNumberGenerator(draw));

        byte[] serialNumber = SerialNumber(leaf);
        // oracle: self-derived; sole guard, with SerialNumberIsDrawnAgainWhenItWouldBeZero,
        // for a serial number whose first octet keeps its top bit while its other bits are kept, set or flipped.
        // RFC 5280 allows any positive encoding, and .NET writes a set top bit with a leading zero octet,
        // so only the library chooses to clear the top bit of the 16 octets drawn.
        Assert.Equal([0x7F, .. draw[1..]], serialNumber);
        Assert.True(new BigInteger(serialNumber, isUnsigned: false, isBigEndian: true) > 0);
        Assert.InRange(serialNumber.Length, 1, 20);
    }

    // RFC 5280 §4.1.2.2: the serial number is positive, so never zero.
    // Clearing the top bit of 80 00 … 00 leaves zero, which is not a positive serial number.
    [Fact]
    public void SerialNumberIsDrawnAgainWhenItWouldBeZero()
    {
        byte[] topBitOnly = new byte[16];
        topBitOnly[0] = 0x80;
        byte[] second = [.. Enumerable.Repeat((byte)0x01, 16)];

        using X509Certificate2 leaf = Issue(random: new SequenceRandomNumberGenerator(topBitOnly, second));

        // oracle: self-derived; sole guard, with SerialNumberIsTheRandomOctetsWithTheTopBitCleared,
        // for a serial number whose first octet keeps its top bit while its other bits are kept, set or flipped.
        // That 80 00 … 00 becomes zero, and that the next draw becomes the serial number as drawn,
        // follow from the library's own way of making the 16 octets positive.
        Assert.Equal(second, SerialNumber(leaf));
    }

    // RFC 5280 §4.1.2.5.1 and §4.1.2.5.2: certificate times are whole seconds,
    // and a notBefore rounded up would issue a certificate that is not yet valid.
    [Fact]
    public void NotBeforeIsTheClockTruncatedToTheSecond()
    {
        using X509Certificate2 leaf = Issue();

        Assert.Equal(NowInSeconds.UtcDateTime, leaf.NotBefore.ToUniversalTime());
    }

    // CONTRACT.agent-identity.md §4: the lifetime is a server setting.
    // RFC 5280 §4.1.2.5: a certificate holds whole seconds, so a fraction of a second in the lifetime is dropped,
    // since rounding it up would exceed the lifetime.
    [Theory]
    [InlineData(0)]
    [InlineData(500)]
    public void NotAfterIsNotBeforePlusTheWholeSecondsOfTheLifetime(int lifetimeMilliseconds)
    {
        TimeSpan lifetime = TimeSpan.FromDays(30) + TimeSpan.FromMilliseconds(lifetimeMilliseconds);

        using X509Certificate2 leaf = Issue(lifetime: lifetime);

        Assert.Equal(NowInSeconds.AddDays(30).UtcDateTime, leaf.NotAfter.ToUniversalTime());
    }

    // CONTRACT.agent-identity.md §4: the lifetime is capped at the issuing root's notAfter.
    [Fact]
    public void NotAfterIsCappedAtTheNotAfterOfTheIssuer()
    {
        using X509Certificate2 root = CreateRoot(Now.AddDays(-1), NowInSeconds.AddDays(10));

        using X509Certificate2 leaf = Issue(lifetime: TimeSpan.FromDays(90), root: root);

        Assert.Equal(NowInSeconds.AddDays(10).UtcDateTime, leaf.NotAfter.ToUniversalTime());
    }

    // CONTRACT.agent-identity.md §4: the lifetime is a server setting with a default of 90 days.
    [Fact]
    public void DefaultLifetimeIs90Days()
    {
        Assert.Equal(TimeSpan.FromDays(90), IdentityCertificateIssuer.DefaultLifetime);
    }

    // CONTRACT.agent-identity.md §4: the lifetime is a server setting,
    // and reading a moving clock twice would give the certificate a validity other than its lifetime.
    [Fact]
    public void ReadsTheClockOnce()
    {
        using X509Certificate2 leaf = Issue(clock: new AdvancingTimeProvider(Now, TimeSpan.FromHours(1)));

        Assert.Equal(NowInSeconds.UtcDateTime, leaf.NotBefore.ToUniversalTime());
        Assert.Equal((NowInSeconds + Lifetime).UtcDateTime, leaf.NotAfter.ToUniversalTime());
    }

    // The certificate chains to the root that issued it, for client authentication.
    // RFC 5280 §6 path validation, as X509Chain runs it, with the CONTRACT.agent-identity.md §4 EKU clientAuth.
    [Fact]
    public void ChainsToTheIssuer()
    {
        using X509Certificate2 leaf = Issue();
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = Now.AddHours(1).UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuth));

        bool built = chain.Build(leaf);

        Assert.True(built, string.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation)));
        Assert.Equal(2, chain.ChainElements.Count);
    }

    // Security invariant 2: the authority mints the subject, and a CSR supplies only a verified public key.
    [Fact]
    public void IgnoresTheSubjectAndExtensionsOfTheCsr()
    {
        CertificateRequest request = new("CN=Administrator, O=Another Identity", _agentKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        CertificateSigningRequest csr = CertificateSigningRequest.Validate(request.CreateSigningRequest()).Csr!;

        using X509Certificate2 leaf = Issue(csr: csr);

        Assert.Equal($"CN={IdentityIdText}", leaf.Subject);
        Assert.Null(leaf.Extensions[BasicConstraintsOid]);
        X509EnhancedKeyUsageExtension usage =
            Assert.IsType<X509EnhancedKeyUsageExtension>(leaf.Extensions[ExtendedKeyUsageOid]);
        Assert.Equal([ClientAuth], usage.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value));
    }

    // RFC 5280 §4.1.2.5: a certificate holds whole seconds,
    // so a lifetime under one second would end in the second it begins.
    [Theory]
    [InlineData(0)]
    [InlineData(-1_000)]
    [InlineData(999)]
    public void ThrowsForLifetimeShorterThanOneSecond(int milliseconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Issue(lifetime: TimeSpan.FromMilliseconds(milliseconds)));
    }

    // CONTRACT.agent-identity.md §4: notAfter is at most the issuer's notAfter,
    // so an issuer that expires by notBefore leaves no validity.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ThrowsWhenTheIssuerExpiresByNotBefore(int seconds)
    {
        using X509Certificate2 root = CreateRoot(Now.AddDays(-30), NowInSeconds.AddSeconds(seconds));

        Assert.Throws<ArgumentException>(() => Issue(root: root));
    }

    // RFC 5280 §4.2.1.1: the authority key identifier repeats the issuer's subject key identifier.
    [Fact]
    public void ThrowsWhenTheIssuerHasNoSubjectKeyIdentifier()
    {
        using X509Certificate2 root = CreateRoot(Now.AddDays(-1), Now.AddYears(10), withSubjectKeyIdentifier: false);

        Assert.Throws<ArgumentException>(() => Issue(root: root));
    }

    // INTENT.md: code that acts for an identity takes the identity that the signature check produced.
    // The renew request is signed by device-a, whose identity ID the vector file gives.
    [Fact]
    public async Task RenewalCertifiesTheKeyOfTheCsrForTheIdentityThatSignedTheRenewRequest()
    {
        Assert.Equal(Guid.Parse(IdentityIdText), TestVectors.Instance.Key("device-a").IdentityId);
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        using X509Certificate2 leaf = IssueForRenewal(renewing);

        Assert.Equal($"CN={IdentityIdText}", leaf.Subject);
        Assert.Equal(_agentKey.ExportSubjectPublicKeyInfo(), leaf.PublicKey.ExportSubjectPublicKeyInfo());
    }

    // INTENT.md: code that acts for an identity takes the identity that the signature check produced,
    // and only a renew request proves the identity that a renewal acts for.
    // An identity that proved its key for another operation never had a renew request accepted for it.
    [Theory]
    [InlineData(nameof(IdentityCertificateIssuer), AgentOperation.Confirm)]
    [InlineData(nameof(IdentityCertificateIssuer), AgentOperation.CheckIn)]
    [InlineData(nameof(IdentityCertificateIssuer), AgentOperation.Connect)]
    [InlineData(nameof(RenewalRules), AgentOperation.Confirm)]
    [InlineData(nameof(RenewalRules), AgentOperation.CheckIn)]
    [InlineData(nameof(RenewalRules), AgentOperation.Connect)]
    public async Task RenewalThrowsForAnIdentityAuthenticatedForAnotherOperation(
        string renewal,
        AgentOperation operation)
    {
        AuthenticatedIdentity identity = await TestIdentity.AuthenticateAsync(operation);

        ArgumentException exception = Assert.Throws<ArgumentException>(() => Renewals[renewal](identity));

        Assert.Equal("renewing", exception.ParamName);
    }

    // INTENT.md: a renewal acts for the identity that a renew request proved, and null is no identity;
    // the .NET Framework Design Guidelines throw ArgumentNullException for a null argument that is not allowed.
    [Theory]
    [InlineData(nameof(IdentityCertificateIssuer))]
    [InlineData(nameof(RenewalRules))]
    public void RenewalThrowsForANullIdentity(string renewal)
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => Renewals[renewal](null!));

        Assert.Equal("renewing", exception.ParamName);
    }

    // The two calls that act for a renewing identity, named by the class of each.
    private Dictionary<string, Action<AuthenticatedIdentity>> Renewals => new()
    {
        [nameof(IdentityCertificateIssuer)] = renewing => IssueForRenewal(renewing).Dispose(),
        [nameof(RenewalRules)] = renewing => RenewalRules.Decide(renewing, null),
    };

    private X509Certificate2 IssueForRenewal(AuthenticatedIdentity renewing)
    {
        return IdentityCertificateIssuer.Issue(
            renewing,
            _csr,
            new TestRootSigner(_root, _rootKey),
            Lifetime,
            new FixedTimeProvider(Now),
            _random);
    }

    private X509Certificate2 Issue(
        TimeSpan? lifetime = null,
        TimeProvider? clock = null,
        RandomNumberGenerator? random = null,
        X509Certificate2? root = null,
        CertificateSigningRequest? csr = null)
    {
        return IdentityCertificateIssuer.Issue(
            IdentityId,
            csr ?? _csr,
            new TestRootSigner(root ?? _root, _rootKey),
            lifetime ?? Lifetime,
            clock ?? new FixedTimeProvider(Now),
            random ?? _random);
    }

    private X509Certificate2 CreateRoot(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool withSubjectKeyIdentifier = true)
    {
        CertificateRequest request = new("CN=Test Agent Identity Root", _rootKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        if (withSubjectKeyIdentifier)
        {
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        }

        return request.CreateSelfSigned(notBefore, notAfter);
    }

    // RFC 5280 §4.1: TBSCertificate ::= SEQUENCE { [0] EXPLICIT version, serialNumber INTEGER, ... }.
    private static byte[] SerialNumber(X509Certificate2 certificate)
    {
        AsnReader certificateReader = new AsnReader(certificate.RawData, AsnEncodingRules.DER).ReadSequence();
        AsnReader tbsCertificate = certificateReader.ReadSequence();
        _ = tbsCertificate.ReadEncodedValue();

        return tbsCertificate.ReadIntegerBytes().ToArray();
    }

    private sealed class TestRootSigner(X509Certificate2 certificate, ECDsa key) : IRootSigner
    {
        public X509Certificate2 Certificate => certificate;

        public X509SignatureGenerator SignatureGenerator => X509SignatureGenerator.CreateForECDsa(key);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }

    // Moves forward by one step at each reading.
    private sealed class AdvancingTimeProvider(DateTimeOffset start, TimeSpan step) : TimeProvider
    {
        private int _readings;

        public override DateTimeOffset GetUtcNow()
        {
            return start + (step * _readings++);
        }
    }

    // Returns the given draws in order and fails when asked for another.
    private sealed class SequenceRandomNumberGenerator(params byte[][] draws) : RandomNumberGenerator
    {
        private int _next;

        public override void GetBytes(byte[] data)
        {
            GetBytes(data.AsSpan());
        }

        public override void GetBytes(Span<byte> data)
        {
            byte[] draw = draws[_next++];
            Assert.Equal(draw.Length, data.Length);
            draw.CopyTo(data);
        }
    }
}
