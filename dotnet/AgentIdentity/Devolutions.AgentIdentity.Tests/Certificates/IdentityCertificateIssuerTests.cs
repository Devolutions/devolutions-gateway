using System.Formats.Asn1;
using System.Numerics;
using System.Reflection;
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

    // 12:00:00.750 UTC, whose fraction a certificate cannot hold.
    private static readonly DateTimeOffset NowInSeconds = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = NowInSeconds.AddMilliseconds(750);

    private static readonly TimeSpan Lifetime = TimeSpan.FromDays(30);

    // What the injected generator draws for a serial number, by name:
    // all ones, which as drawn would encode a negative INTEGER,
    // and the top bit alone, which is zero once that bit is cleared, followed by a second draw.
    private static readonly Dictionary<string, byte[]> SerialNumberDraws = new()
    {
        ["all ones"] = [.. Enumerable.Repeat((byte)0xFF, 16)],
        ["the top bit alone, then all 01"] = [0x80, .. new byte[15], .. Enumerable.Repeat((byte)0x01, 16)],
    };

    public static TheoryData<string> SerialNumberDrawNames => new(SerialNumberDraws.Keys);

    // A token that can create an identity.
    // The `u` of the token that enrolls the identity, and the CSR of the enrollment, which names it.
    private const string TokenUrl = "https://host/dvls";

    private static readonly CertificateSigningRequest EnrollingCsr = TestEnrollmentUrl.Csr(TokenUrl);

    private static EnrollmentTokenState UsableToken =>
        new(false, TokenUrl, Now.AddDays(1), maxUses: 10, identitiesCreated: 0);

    // A decision of each outcome but the creation of an identity: an expired token's refusal and a replay.
    private static Dictionary<EnrollmentOutcome, EnrollmentDecision> DecisionsButCreateIdentity => new()
    {
        [EnrollmentOutcome.Reject] =
            EnrollmentRules.Decide(
                new(false, TokenUrl, Now, maxUses: 10, identitiesCreated: 0),
                EnrollingCsr,
                null,
                Now),
        [EnrollmentOutcome.ReturnExistingIdentity] = EnrollmentRules.Decide(
            UsableToken,
            EnrollingCsr,
            IssuedKeyMatch.ForIdentity(Guid.Parse(IdentityIdText), true, false, CertificateStatus.Current),
            Now),
    };

    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly RandomNumberGenerator _random = RandomNumberGenerator.Create();
    private readonly X509Certificate2 _root;
    private readonly CertificateSigningRequest _csr;

    // The decision that creates the identity whose certificate each test issues, unless the test passes another.
    private readonly EnrollmentDecision _creating = EnrollmentRules.Decide(UsableToken, EnrollingCsr, null, Now);

    // The ID that the decision minted, as CONTRACT.agent-identity.md §1 writes IDs:
    // Guid.ToString("D") writes a UUID lowercase and hyphenated.
    private string NewIdentityIdText => Assert.NotNull(_creating.NewIdentityId).ToString("D");

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

    // The certificate is for the P-256 key of the CSR.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void CertifiesTheKeyOfTheCsr()
    {
        using X509Certificate2 leaf = Issue();

        Assert.Equal(_agentKey.ExportSubjectPublicKeyInfo(), leaf.PublicKey.ExportSubjectPublicKeyInfo());
    }

    // CN=<identity_id>, and the root's subject as the issuer.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void SubjectIsTheCommonNameOfTheIdentity()
    {
        using X509Certificate2 leaf = Issue();

        X500RelativeDistinguishedName name = Assert.Single(leaf.SubjectName.EnumerateRelativeDistinguishedNames());
        Assert.Equal("2.5.4.3", name.GetSingleElementType().Value);
        Assert.Equal(NewIdentityIdText, name.GetSingleElementValue());
        // oracle: spec RFC 5280 §4.1.2.4
        Assert.Equal(_root.SubjectName.RawData, leaf.IssuerName.RawData);
    }

    // CONTRACT.agent-identity.md §4: SAN URI urn:uuid:<identity_id>.
    // RFC 5280 §4.2.1.6: GeneralNames is a SEQUENCE OF GeneralName, and a URI is [6] IA5String;
    // with a subject present, the extension is not critical.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: spec RFC 5280 §4.2.1.6
    [Fact]
    public void AlternativeNameIsTheUrnUuidOfTheIdentity()
    {
        using X509Certificate2 leaf = Issue();
        X509Extension extension =
            Assert.IsType<X509Extension>(leaf.Extensions[SubjectAlternativeNameOid], exactMatch: false);

        AsnReader names = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
        string uri = names.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));

        Assert.Equal($"urn:uuid:{NewIdentityIdText}", uri);
        Assert.False(names.HasData);
        Assert.False(extension.Critical);
    }

    // EKU clientAuth.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void ExtendedKeyUsageIsClientAuthenticationOnly()
    {
        using X509Certificate2 leaf = Issue();
        X509EnhancedKeyUsageExtension extension =
            Assert.IsType<X509EnhancedKeyUsageExtension>(leaf.Extensions[ExtendedKeyUsageOid]);

        Assert.Equal([ClientAuth], extension.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value));
    }

    // CONTRACT.agent-identity.md §4: KeyUsage digitalSignature; RFC 5280 §4.2.1.3: marked critical.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void KeyUsageIsCriticalDigitalSignatureOnly()
    {
        using X509Certificate2 leaf = Issue();
        X509KeyUsageExtension extension = Assert.IsType<X509KeyUsageExtension>(leaf.Extensions[KeyUsageOid]);

        Assert.Equal(X509KeyUsageFlags.DigitalSignature, extension.KeyUsages);
        // oracle: spec RFC 5280 §4.2.1.3
        Assert.True(extension.Critical);
    }

    // The key identifier of the issuer's subject key identifier, in a non-critical extension.
    // oracle: spec RFC 5280 §4.2.1.1
    // oracle: spec RFC 5280 §4.2.1.2
    [Fact]
    public void AuthorityKeyIdentifierIsTheSubjectKeyIdentifierOfTheIssuer()
    {
        using X509Certificate2 leaf = Issue();
        X509AuthorityKeyIdentifierExtension authority =
            Assert.IsType<X509AuthorityKeyIdentifierExtension>(leaf.Extensions[AuthorityKeyIdentifierOid]);
        X509SubjectKeyIdentifierExtension issuer =
            Assert.IsType<X509SubjectKeyIdentifierExtension>(_root.Extensions[SubjectKeyIdentifierOid]);

        Assert.Equal(issuer.SubjectKeyIdentifierBytes.ToArray(), authority.KeyIdentifier?.ToArray());
        Assert.False(authority.Critical);
    }

    // A subject key identifier, in a non-critical extension.
    // oracle: spec RFC 5280 §4.2.1.2
    [Fact]
    public void SubjectKeyIdentifierIsNotCritical()
    {
        using X509Certificate2 leaf = Issue();
        X509SubjectKeyIdentifierExtension extension =
            Assert.IsType<X509SubjectKeyIdentifierExtension>(leaf.Extensions[SubjectKeyIdentifierOid]);

        Assert.False(extension.Critical);
    }

    // The leaf carries SAN, EKU and KeyUsage, and no other extension except an authority key identifier, a subject
    // key identifier and the enrollment URL extension, so no basicConstraints.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void HasExactlyTheProfileExtensions()
    {
        using X509Certificate2 leaf = Issue();

        IEnumerable<string?> extensions = leaf.Extensions.Select(extension => extension.Oid?.Value);
        string[] expected =
        [
            TestEnrollmentUrl.Oid,
            SubjectKeyIdentifierOid,
            KeyUsageOid,
            SubjectAlternativeNameOid,
            AuthorityKeyIdentifierOid,
            ExtendedKeyUsageOid,
        ];

        Assert.Equal(expected, extensions.Order(StringComparer.Ordinal));
        // oracle: spec RFC 5280 §4.1.2.1
        Assert.Equal(3, leaf.Version);
    }

    // The enrollment URL extension is non-critical and holds as an IA5String the `u` of the token that enrolled the
    // identity, without trailing slashes, and a leaf carries it exactly once.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void NamesTheEnrollmentUrlOfTheDecision()
    {
        using X509Certificate2 leaf = Issue();

        Assert.Equal((false, TokenUrl), Assert.Single(EnrollmentUrls(leaf)));
    }

    // Every certificate issued for an identity carries the same enrollment URL, which the authority keeps with it,
    // so a renewal names the URL it is given.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public async Task RenewalNamesTheEnrollmentUrlOfTheIdentity()
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        using X509Certificate2 leaf = IssueForRenewal(renewing, "https://host/psu");

        Assert.Equal((false, "https://host/psu"), Assert.Single(EnrollmentUrls(leaf)));
    }

    // The value is an IA5String, which holds only ASCII, of a URL without trailing slashes; an empty one names nothing.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData("")]
    [InlineData("https://host/dvls/")]
    [InlineData("https://bücher.example/dvls")]
    public async Task RenewalThrowsForAnEnrollmentUrlOutsideTheExtensionForm(string enrollmentUrl)
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        ArgumentException exception = Assert.Throws<ArgumentException>(() => IssueForRenewal(renewing, enrollmentUrl));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("enrollmentUrl", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public async Task RenewalThrowsForANullEnrollmentUrl()
    {
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => IssueForRenewal(renewing, null!));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("enrollmentUrl", exception.ParamName);
    }

    // A positive INTEGER, so never zero, of at most 20 octets, whatever the injected generator draws.
    // oracle: spec RFC 5280 §4.1.2.2
    [Theory]
    [MemberData(nameof(SerialNumberDrawNames))]
    public void SerialNumberIsAPositiveIntegerOfAtMost20Octets(string draws)
    {
        using X509Certificate2 leaf = Issue(random: new ScriptedRandomNumberGenerator(SerialNumberDraws[draws]));

        byte[] serialNumber = SerialNumber(leaf);
        Assert.True(new BigInteger(serialNumber, isUnsigned: false, isBigEndian: true) > 0);
        Assert.InRange(serialNumber.Length, 1, 20);
    }

    // The serial number is the 16 octets drawn with their top bit cleared.
    // RFC 5280 allows any positive encoding, and .NET writes a set top bit with a leading zero octet,
    // so only the library chooses to clear the top bit of the 16 octets drawn.
    // oracle: mutant a serial number whose first octet keeps its top bit while its other bits are kept,
    // set or flipped
    [Fact]
    public void SerialNumberIsTheRandomOctetsWithTheTopBitCleared()
    {
        byte[] draw = [.. Enumerable.Repeat((byte)0xFF, 16)];

        using X509Certificate2 leaf = Issue(random: new ScriptedRandomNumberGenerator(draw));

        Assert.Equal([0x7F, .. draw[1..]], SerialNumber(leaf));
    }

    // The lifetime is a server setting.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void NotAfterIsNotBeforePlusTheLifetime()
    {
        using X509Certificate2 leaf = Issue(lifetime: TimeSpan.FromDays(30));

        Assert.Equal(TimeSpan.FromDays(30), leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime());
    }

    // The lifetime is capped at the issuing root's notAfter.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void NotAfterIsCappedAtTheNotAfterOfTheIssuer()
    {
        using X509Certificate2 root = CreateRoot(Now.AddDays(-1), NowInSeconds.AddDays(10));

        using X509Certificate2 leaf = Issue(lifetime: TimeSpan.FromDays(90), root: root);

        Assert.Equal(NowInSeconds.AddDays(10).UtcDateTime, leaf.NotAfter.ToUniversalTime());
    }

    // The lifetime is a server setting with a default of 90 days.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void DefaultLifetimeIs90Days()
    {
        Assert.Equal(TimeSpan.FromDays(90), IdentityCertificateIssuer.DefaultLifetime);
    }

    // The lifetime is a server setting,
    // and reading a moving clock twice would give the certificate a validity other than its lifetime.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    [Fact]
    public void ReadsTheClockOnce()
    {
        using X509Certificate2 leaf = Issue(clock: new SteppingTimeProvider(Now, Now.AddHours(1), Now.AddHours(2)));

        Assert.Equal(Lifetime, leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime());
    }

    // The certificate chains to the root that issued it, for client authentication.
    // RFC 5280 §6 path validation, as X509Chain runs it, with the CONTRACT.agent-identity.md §4 EKU clientAuth.
    // oracle: spec RFC 5280 §6
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public void IgnoresTheSubjectAndExtensionsOfTheCsr()
    {
        CertificateRequest request = new("CN=Administrator, O=Another Identity", _agentKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        CertificateSigningRequest csr = CertificateSigningRequest.Validate(request.CreateSigningRequest()).Csr!;

        using X509Certificate2 leaf = Issue(csr: csr);

        Assert.Equal($"CN={NewIdentityIdText}", leaf.Subject);
        // The leaf carries no basicConstraints, so a leaf can never act as a CA.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        Assert.Null(leaf.Extensions[BasicConstraintsOid]);
        X509EnhancedKeyUsageExtension usage =
            Assert.IsType<X509EnhancedKeyUsageExtension>(leaf.Extensions[ExtendedKeyUsageOid]);
        Assert.Equal([ClientAuth], usage.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value));
    }

    // A certificate holds whole seconds, so a lifetime under one second would end in the second it begins.
    // oracle: spec RFC 5280 §4.1.2.5
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
    [Theory]
    [InlineData(0)]
    [InlineData(-1_000)]
    [InlineData(999)]
    public void ThrowsForLifetimeShorterThanOneSecond(int milliseconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Issue(lifetime: TimeSpan.FromMilliseconds(milliseconds)));
    }

    // notAfter is at most the issuer's notAfter, so an issuer that expires by notBefore leaves no validity.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ThrowsWhenTheIssuerExpiresByNotBefore(int seconds)
    {
        using X509Certificate2 root = CreateRoot(Now.AddDays(-30), NowInSeconds.AddSeconds(seconds));

        Assert.Throws<ArgumentException>(() => Issue(root: root));
    }

    // A conforming CA certificate carries a subject key identifier,
    // which the authority key identifier of each certificate it issues repeats.
    // oracle: spec RFC 5280 §4.2.1.2
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void ThrowsWhenTheIssuerHasNoSubjectKeyIdentifier()
    {
        using X509Certificate2 root = CreateRoot(Now.AddDays(-1), Now.AddYears(10), withSubjectKeyIdentifier: false);

        Assert.Throws<ArgumentException>(() => Issue(root: root));
    }

    // Every certificate in a chain is signed with ecdsa-with-SHA256 by a P-256 key or with ecdsa-with-SHA384 by a P-384
    // key, never with RSA, and every CA certificate, the root included, carries basicConstraints with cA set and key
    // usage with keyCertSign, so the library issues nothing under a root that breaks one of these.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [MemberData(nameof(IssuersOutsideTheChainProfileNames))]
    public void ThrowsForAnIssuerOutsideTheChainProfile(string issuer)
    {
        using OwnedRootSigner root = IssuersOutsideTheChainProfile[issuer]();

        ArgumentException exception = Assert.Throws<ArgumentException>(() => IdentityCertificateIssuer.Issue(
            _creating,
            _csr,
            root,
            Lifetime,
            new FixedTimeProvider(Now),
            _random));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("issuer", exception.ParamName);
    }

    public static TheoryData<string> IssuersOutsideTheChainProfileNames => new(IssuersOutsideTheChainProfile.Keys);

    // A root of each allowed curve signs the certificate with the signature algorithm of its curve,
    // and the certificate chains to it: ecdsa-with-SHA256 for P-256 and ecdsa-with-SHA384 for P-384 (RFC 5758 §3.2).
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: spec RFC 5758 §3.2
    [Theory]
    [InlineData("P-256", "1.2.840.10045.4.3.2")]
    [InlineData("P-384", "1.2.840.10045.4.3.3")]
    public void SignsWithTheAlgorithmOfTheIssuerCurve(string curve, string signatureAlgorithm)
    {
        using OwnedRootSigner root = EcdsaProfileRoot(
            curve == "P-256" ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);

        using X509Certificate2 leaf = IdentityCertificateIssuer.Issue(
            _creating,
            _csr,
            root,
            Lifetime,
            new FixedTimeProvider(Now),
            _random);

        Assert.Equal(signatureAlgorithm, leaf.SignatureAlgorithm.Value);
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root.Certificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = Now.AddHours(1).UtcDateTime;
        Assert.True(chain.Build(leaf), string.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation)));
    }

    // Roots that break the chain profile, by what they break; every other part of each is a conforming CA root.
    private static Dictionary<string, Func<OwnedRootSigner>> IssuersOutsideTheChainProfile => new()
    {
        ["an RSA key"] = () =>
        {
            RSA key = RSA.Create(2048);
            return new OwnedRootSigner(
                ProfileRoot(new CertificateRequest(RootName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)),
                X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
                key);
        },
        ["a P-521 key"] = () => EcdsaProfileRoot(ECCurve.NamedCurves.nistP521),
        ["a P-256 certificate whose signer is RSA"] = () =>
        {
            ECDsa certificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            RSA key = RSA.Create(2048);
            X509Certificate2 certificate =
                ProfileRoot(new CertificateRequest(RootName, certificateKey, HashAlgorithmName.SHA256));
            certificateKey.Dispose();
            return new OwnedRootSigner(
                certificate,
                X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
                key);
        },
        ["no basicConstraints"] = () => EcdsaProfileRoot(ECCurve.NamedCurves.nistP256, [CaKeyUsage()]),
        ["basicConstraints without cA"] = () => EcdsaProfileRoot(
            ECCurve.NamedCurves.nistP256,
            [new X509BasicConstraintsExtension(false, false, 0, true), CaKeyUsage()]),
        ["no key usage"] = () => EcdsaProfileRoot(ECCurve.NamedCurves.nistP256, [CaBasicConstraints()]),
        ["key usage without keyCertSign"] = () => EcdsaProfileRoot(
            ECCurve.NamedCurves.nistP256,
            [
                CaBasicConstraints(),
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign, true),
            ]),
    };

    // Code that acts for an identity takes it as a type only the library's checks can create;
    // for a new identity, that is the enrollment decision that creates it.
    // A refusal creates no identity, and a replay returns the identity's current chain rather than a new certificate.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Authenticated identity
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData(EnrollmentOutcome.Reject)]
    [InlineData(EnrollmentOutcome.ReturnExistingIdentity)]
    public void ThrowsForADecisionThatCreatesNoIdentity(EnrollmentOutcome outcome)
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => Issue(creating: DecisionsButCreateIdentity[outcome]));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("creating", exception.ParamName);
    }

    // A null argument throws ArgumentNullException, whose ParamName names it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void ThrowsForANullDecision()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => IdentityCertificateIssuer.Issue(
            (EnrollmentDecision)null!,
            _csr,
            new TestRootSigner(_root, _rootKey),
            Lifetime,
            new FixedTimeProvider(Now),
            _random));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("creating", exception.ParamName);
    }

    // An identity is never taken from a value that a caller sent,
    // so no public member that issues a certificate takes an identity ID.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Authenticated identity
    [Fact]
    public void NoPublicMemberIssuesACertificateForAnIdentityId()
    {
        const BindingFlags declared = BindingFlags.Public | BindingFlags.NonPublic
            | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        Type[] identityIds = [typeof(Guid), typeof(Guid?)];

        IEnumerable<string> issuers = typeof(IdentityCertificateIssuer).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMethods(declared)
                .Where(method => method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly)
                .Where(method => method.ReturnType == typeof(X509Certificate2))
                .Where(method => method.GetParameters()
                    .Any(parameter => identityIds.Contains(parameter.ParameterType)))
                .Select(method => $"{type.Name}.{method.Name}"));

        Assert.Empty(issuers);
    }

    // Code that acts for an identity takes the identity that the signature check produced.
    // The renew request is signed by device-a, whose identity ID the vector file gives.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Authenticated identity
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Fact]
    public async Task RenewalCertifiesTheKeyOfTheCsrForTheIdentityThatSignedTheRenewRequest()
    {
        // oracle: reference docs/agent-identity/test-vectors.json keys.device-a
        Assert.Equal(Guid.Parse(IdentityIdText), TestVectors.Instance.Key("device-a").IdentityId);
        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);

        using X509Certificate2 leaf = IssueForRenewal(renewing);

        Assert.Equal($"CN={IdentityIdText}", leaf.Subject);
        Assert.Equal(_agentKey.ExportSubjectPublicKeyInfo(), leaf.PublicKey.ExportSubjectPublicKeyInfo());
    }

    // Code that acts for an identity takes the identity that the signature check produced,
    // and only a renew request proves the identity that a renewal acts for.
    // An identity that proved its key for another operation never had a renew request accepted for it.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Authenticated identity
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §renew
    // oracle: spec Framework Design Guidelines §Validating Arguments
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

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("renewing", exception.ParamName);
    }

    // INTENT.md: a renewal acts for the identity that a renew request proved, and null is no identity;
    // the .NET Framework Design Guidelines throw ArgumentNullException for a null argument that is not allowed.
    // oracle: intent dotnet/AgentIdentity/INTENT.md §Authenticated identity
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [InlineData(nameof(IdentityCertificateIssuer))]
    [InlineData(nameof(RenewalRules))]
    public void RenewalThrowsForANullIdentity(string renewal)
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(() => Renewals[renewal](null!));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("renewing", exception.ParamName);
    }

    // The two calls that act for a renewing identity, named by the class of each.
    private Dictionary<string, Action<AuthenticatedIdentity>> Renewals => new()
    {
        [nameof(IdentityCertificateIssuer)] = renewing => IssueForRenewal(renewing).Dispose(),
        [nameof(RenewalRules)] = renewing => RenewalRules.Decide(renewing, null),
    };

    private X509Certificate2 IssueForRenewal(AuthenticatedIdentity renewing, string enrollmentUrl = TokenUrl)
    {
        return IdentityCertificateIssuer.Issue(
            renewing,
            enrollmentUrl,
            _csr,
            new TestRootSigner(_root, _rootKey),
            Lifetime,
            new FixedTimeProvider(Now),
            _random);
    }

    private X509Certificate2 Issue(
        EnrollmentDecision? creating = null,
        TimeSpan? lifetime = null,
        TimeProvider? clock = null,
        RandomNumberGenerator? random = null,
        X509Certificate2? root = null,
        CertificateSigningRequest? csr = null)
    {
        return IdentityCertificateIssuer.Issue(
            creating ?? _creating,
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

    // RFC 5280 §4.1: Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING };
    // the enrollment URL extensions of a certificate, each with its criticality and its IA5String value.
    private static (bool Critical, string Value)[] EnrollmentUrls(X509Certificate2 certificate)
    {
        return
        [
            .. certificate.Extensions
                .Where(extension => extension.Oid?.Value == TestEnrollmentUrl.Oid)
                .Select(extension =>
                {
                    AsnReader value = new(extension.RawData, AsnEncodingRules.DER);
                    string url = value.ReadCharacterString(UniversalTagNumber.IA5String);
                    value.ThrowIfNotEmpty();
                    return (extension.Critical, url);
                }),
        ];
    }

    // RFC 5280 §4.1: TBSCertificate ::= SEQUENCE { [0] EXPLICIT version, serialNumber INTEGER, ... }.
    private static byte[] SerialNumber(X509Certificate2 certificate)
    {
        AsnReader certificateReader = new AsnReader(certificate.RawData, AsnEncodingRules.DER).ReadSequence();
        AsnReader tbsCertificate = certificateReader.ReadSequence();
        _ = tbsCertificate.ReadEncodedValue();

        return tbsCertificate.ReadIntegerBytes().ToArray();
    }

    private const string RootName = "CN=Test Agent Identity Root";

    // A self-signed root with a subject key identifier and the given extensions,
    // by default those of a CA root: basicConstraints with cA set, and key usage with keyCertSign.
    private static X509Certificate2 ProfileRoot(CertificateRequest request, X509Extension[]? extensions = null)
    {
        foreach (X509Extension extension in extensions ?? [CaBasicConstraints(), CaKeyUsage()])
        {
            request.CertificateExtensions.Add(extension);
        }

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(Now.AddDays(-1), Now.AddYears(10));
    }

    private static OwnedRootSigner EcdsaProfileRoot(ECCurve curve, X509Extension[]? extensions = null)
    {
        ECDsa key = ECDsa.Create(curve);

        return new OwnedRootSigner(
            ProfileRoot(new CertificateRequest(RootName, key, HashAlgorithmName.SHA256), extensions),
            X509SignatureGenerator.CreateForECDsa(key),
            key);
    }

    private static X509BasicConstraintsExtension CaBasicConstraints()
    {
        return new X509BasicConstraintsExtension(true, false, 0, true);
    }

    private static X509KeyUsageExtension CaKeyUsage()
    {
        return new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true);
    }

    // A root signer that owns its certificate and the key behind its generator.
    private sealed class OwnedRootSigner(
        X509Certificate2 certificate,
        X509SignatureGenerator generator,
        IDisposable key)
        : IRootSigner, IDisposable
    {
        public X509Certificate2 Certificate => certificate;

        public X509SignatureGenerator SignatureGenerator => generator;

        public void Dispose()
        {
            certificate.Dispose();
            key.Dispose();
        }
    }

    private sealed class TestRootSigner(X509Certificate2 certificate, ECDsa key) : IRootSigner
    {
        public X509Certificate2 Certificate => certificate;

        public X509SignatureGenerator SignatureGenerator => X509SignatureGenerator.CreateForECDsa(key);
    }
}
