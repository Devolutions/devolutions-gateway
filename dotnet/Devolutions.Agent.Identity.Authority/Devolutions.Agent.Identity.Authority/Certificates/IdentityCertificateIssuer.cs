using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Issues identity certificates, the leaf certificates through which agents authenticate.
/// </summary>
public static class IdentityCertificateIssuer
{
    // RFC 5280 §4.2.1.12: id-kp-clientAuth.
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    private const string SubjectKeyIdentifierOid = "2.5.29.14";

    private const string KeyUsageOid = "2.5.29.15";

    private const string BasicConstraintsOid = "2.5.29.19";

    // RFC 5480 §2.1.1: id-ecPublicKey.
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    // RFC 5480 §2.1.1.1: the DER encodings of the namedCurve secp256r1 (P-256) and secp384r1 (P-384).
    private static readonly byte[] P256CurveParameters = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    private static readonly byte[] P384CurveParameters = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

    // RFC 5758 §3.2: the DER AlgorithmIdentifiers of ecdsa-with-SHA256 and ecdsa-with-SHA384,
    // whose parameters are absent.
    private static readonly byte[] EcdsaWithSha256Identifier =
        [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    private static readonly byte[] EcdsaWithSha384Identifier =
        [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

    /// <summary>
    /// The lifetime of an identity certificate when the host sets no other: 90 days.
    /// </summary>
    public static TimeSpan DefaultLifetime { get; } = TimeSpan.FromDays(90);

    /// <summary>
    /// Issues the certificate of the new identity that an enrollment decision creates, for the key of a validated CSR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The certificate has the CSR's key, the subject <c>CN=&lt;identity ID&gt;</c>,
    /// the subject alternative name URI <c>urn:uuid:&lt;identity ID&gt;</c>, the extended key usage clientAuth,
    /// the critical key usage digitalSignature, a subject key identifier,
    /// an authority key identifier equal to the issuer's subject key identifier, and no basic constraints.
    /// The identity ID is <see cref="EnrollmentDecision.NewIdentityId"/>, written lowercase and hyphenated,
    /// and nothing else from the CSR reaches the certificate.
    /// </para>
    /// <para>
    /// It is valid from the current time, truncated to the second, for <paramref name="lifetime"/>,
    /// or until the issuer's <c>notAfter</c> if that comes first; a fraction of a second in the lifetime is dropped.
    /// Its serial number is 16 octets from <paramref name="random"/>, positive and never zero,
    /// and <paramref name="issuer"/> signs it with the ECDSA algorithm of its key's curve.
    /// It names <see cref="EnrollmentDecision.EnrollmentUrl"/> in the enrollment URL extension.
    /// </para>
    /// <para>
    /// Taking the decision rather than an ID keeps the authority from certifying a key for an identity
    /// that no enrollment created.
    /// Requiring the key that the decision was made for keeps it from certifying a key whose lookup no decision saw,
    /// which could be a key already issued.
    /// A renewal certifies a key for an existing identity,
    /// so it uses the overload that takes the renewal decision.
    /// </para>
    /// </remarks>
    /// <param name="creating">
    /// The decision of <see cref="EnrollmentRules.Decide"/> to create the identity,
    /// whose <see cref="EnrollmentDecision.Outcome"/> is <see cref="EnrollmentOutcome.CreateIdentity"/>.
    /// </param>
    /// <param name="csr">
    /// The validated CSR whose key the certificate is for, the key that <paramref name="creating"/> was made for.
    /// </param>
    /// <param name="issuer">The root that signs the certificate.</param>
    /// <param name="lifetime">The certificate lifetime, usually <see cref="DefaultLifetime"/>.</param>
    /// <param name="timeProvider">The clock, read once.</param>
    /// <param name="random">The source of the serial number.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="creating"/> does not create an identity;
    /// or the SHA-256 digest of the <c>SubjectPublicKeyInfo</c> of <paramref name="csr"/> is not the
    /// <see cref="EnrollmentDecision.SubjectPublicKeyInfoSha256"/> of <paramref name="creating"/>;
    /// or the issuer certificate has no subject key identifier, or its <c>notAfter</c> is not after the current second;
    /// or the issuer is outside the chain profile of CONTRACT.agent-identity.md §4:
    /// its certificate has neither a P-256 nor a P-384 key, no basicConstraints with cA set or no key usage with
    /// keyCertSign, or its generator does not sign with ecdsa-with-SHA256 for a P-256 key or ecdsa-with-SHA384 for a
    /// P-384 key, or holds another key than its certificate's.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="lifetime"/> is shorter than one second.
    /// </exception>
    public static X509Certificate2 Issue(
        EnrollmentDecision creating,
        CertificateSigningRequest csr,
        IRootSigner issuer,
        TimeSpan lifetime,
        TimeProvider timeProvider,
        RandomNumberGenerator random)
    {
        ArgumentNullException.ThrowIfNull(creating);

        if (creating.Outcome != EnrollmentOutcome.CreateIdentity)
        {
            throw new ArgumentException("The enrollment decision does not create an identity.", nameof(creating));
        }

        ThrowIfNotTheDecidedKey(csr, creating.SubjectPublicKeyInfoSha256);

        // A decision to create an identity always carries the ID minted for it and the token's URL.
        return Issue(
            creating.NewIdentityId!.Value,
            creating.EnrollmentUrl!,
            csr,
            issuer,
            lifetime,
            timeProvider,
            random);
    }

    // Private so that a certificate is issued only for an identity ID taken from a proof of that identity.
    private static X509Certificate2 Issue(
        Guid identityId,
        string enrollmentUrl,
        CertificateSigningRequest csr,
        IRootSigner issuer,
        TimeSpan lifetime,
        TimeProvider timeProvider,
        RandomNumberGenerator random)
    {
        ArgumentNullException.ThrowIfNull(csr);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(random);

        // A certificate holds whole seconds, so a shorter lifetime would end in the second it begins.
        ArgumentOutOfRangeException.ThrowIfLessThan(lifetime, TimeSpan.FromSeconds(1));

        X509Certificate2 issuerCertificate = issuer.Certificate;

        // RFC 5280 §4.2.1.1: the authority key identifier repeats the issuer's subject key identifier.
        if (issuerCertificate.Extensions[SubjectKeyIdentifierOid] is not X509SubjectKeyIdentifierExtension issuerKeyId)
        {
            throw new ArgumentException("The issuer certificate has no subject key identifier.", nameof(issuer));
        }

        // CONTRACT.agent-identity.md §4: every certificate in a chain is signed with ecdsa-with-SHA256 by a P-256 key
        // or with ecdsa-with-SHA384 by a P-384 key, and every CA certificate carries basicConstraints with cA set
        // and key usage with keyCertSign.
        (HashAlgorithmName hash, byte[] expectedAlgorithm) = SignatureProfile(issuerCertificate.PublicKey)
            ?? throw new ArgumentException(
                "The issuer certificate's key is neither a P-256 nor a P-384 key.",
                nameof(issuer));

        // Read once, so that every check acts on the generator that signs.
        X509SignatureGenerator generator = issuer.SignatureGenerator;
        byte[] signatureAlgorithm = generator.GetSignatureAlgorithmIdentifier(hash);
        if (!signatureAlgorithm.AsSpan().SequenceEqual(expectedAlgorithm))
        {
            throw new ArgumentException(
                "The issuer does not sign with the ECDSA algorithm of its key's curve.",
                nameof(issuer));
        }

        // A generator over another key would sign certificates that do not chain to the issuer certificate.
        PublicKey signerKey = generator.PublicKey;
        byte[] issuerKeyValue = issuerCertificate.PublicKey.EncodedKeyValue.RawData;
        if (!signerKey.EncodedKeyValue.RawData.AsSpan().SequenceEqual(issuerKeyValue))
        {
            throw new ArgumentException(
                "The issuer's generator signs with another key than its certificate's.",
                nameof(issuer));
        }

        if (issuerCertificate.Extensions[BasicConstraintsOid] is not X509BasicConstraintsExtension
            {
                CertificateAuthority: true,
            })
        {
            throw new ArgumentException("The issuer certificate is not a CA certificate.", nameof(issuer));
        }

        if (issuerCertificate.Extensions[KeyUsageOid] is not X509KeyUsageExtension keyUsage
            || !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
        {
            throw new ArgumentException("The issuer certificate's key usage has no keyCertSign.", nameof(issuer));
        }

        DateTimeOffset notBefore = TruncateToSecond(timeProvider.GetUtcNow());
        // UNTESTED: the conversion is exact in the hour that a daylight-saving fall-back repeats,
        // because the local DateTime that X509Certificate2 returns keeps the ambiguous-DST bit,
        // which ToUniversalTime uses.
        // A wrong instant there shifts expiry and validity checks by an hour on hosts outside UTC.
        // Keep the conversion straight from the property: arithmetic, formatting or a DateTimeOffset built from the
        // local value before ToUniversalTime loses the bit.
        DateTimeOffset issuerNotAfter = new(issuerCertificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        if (issuerNotAfter <= notBefore)
        {
            throw new ArgumentException(
                "The issuer certificate expires before the new certificate begins.",
                nameof(issuer));
        }

        // Comparing the lifetime with the time left avoids adding a lifetime too long for DateTimeOffset.
        DateTimeOffset notAfter = lifetime < issuerNotAfter - notBefore
            ? TruncateToSecond(notBefore + lifetime)
            : issuerNotAfter;

        string id = identityId.ToString("D");
        PublicKey publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(csr.SubjectPublicKeyInfo.Span, out _);

        X500DistinguishedNameBuilder subject = new();
        subject.AddCommonName(id);

        SubjectAlternativeNameBuilder alternativeName = new();
        alternativeName.AddUri(new Uri($"urn:uuid:{id}"));

        CertificateRequest request = new(subject.Build(), publicKey, hash);
        OidCollection usages = [new Oid(ClientAuthentication)];

        // RFC 5280 §4.2.1.2, method (1): the SHA-1 hash of the subjectPublicKey bits.
        X509SubjectKeyIdentifierHashAlgorithm keyIdMethod = X509SubjectKeyIdentifierHashAlgorithm.Sha1;
        Collection<X509Extension> extensions = request.CertificateExtensions;
        extensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        extensions.Add(new X509EnhancedKeyUsageExtension(usages, critical: false));
        extensions.Add(alternativeName.Build(critical: false));
        extensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, keyIdMethod, critical: false));
        extensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerKeyId));
        extensions.Add(EnrollmentUrlExtension.Create(enrollmentUrl));

        return request.Create(
            issuerCertificate.SubjectName,
            generator,
            notBefore,
            notAfter,
            NewSerialNumber(random));
    }

    // The hash and the signature AlgorithmIdentifier that CONTRACT.agent-identity.md §4 pairs with the key's curve,
    // or null for a key of another type or curve.
    private static (HashAlgorithmName Hash, byte[] SignatureAlgorithm)? SignatureProfile(PublicKey key)
    {
        byte[]? curve = key.EncodedParameters?.RawData;

        if (key.Oid.Value != EcPublicKeyOid || curve is null)
        {
            return null;
        }

        if (curve.AsSpan().SequenceEqual(P256CurveParameters))
        {
            return (HashAlgorithmName.SHA256, EcdsaWithSha256Identifier);
        }

        if (curve.AsSpan().SequenceEqual(P384CurveParameters))
        {
            return (HashAlgorithmName.SHA384, EcdsaWithSha384Identifier);
        }

        return null;
    }

    /// <summary>
    /// Issues the pending certificate that a renewal decision calls for,
    /// for the identity that signed the renew request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The certificate is the one that the other overload issues, with the identity ID of the
    /// <see cref="AuthenticatedIdentity"/> that <paramref name="issuing"/> was decided for
    /// and <paramref name="enrollmentUrl"/> in the enrollment URL extension.
    /// </para>
    /// <para>
    /// Only <see cref="RenewalRules.Decide"/> produces a decision, from the identity that the signature check produced,
    /// so taking the decision rather than an ID keeps a renewal from certifying a key for an identity that a request
    /// only named.
    /// Requiring the key that the decision was made for keeps it from certifying a key whose lookup no decision saw,
    /// which could be a key already issued.
    /// </para>
    /// </remarks>
    /// <param name="issuing">
    /// The decision of <see cref="RenewalRules.Decide"/> to issue a pending certificate,
    /// whose <see cref="RenewalDecision.Outcome"/> is <see cref="RenewalOutcome.IssuePendingCertificate"/>.
    /// </param>
    /// <param name="enrollmentUrl">
    /// The identity's enrollment URL, the <see cref="EnrollmentDecision.EnrollmentUrl"/> of the decision that created
    /// it, which every certificate of the identity names.
    /// </param>
    /// <param name="csr">
    /// The validated CSR whose key the certificate is for, the key that <paramref name="issuing"/> was made for.
    /// </param>
    /// <param name="issuer">The root that signs the certificate.</param>
    /// <param name="lifetime">The certificate lifetime, usually <see cref="DefaultLifetime"/>.</param>
    /// <param name="timeProvider">The clock, read once.</param>
    /// <param name="random">The source of the serial number.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="issuing"/> does not issue a pending certificate;
    /// or <paramref name="enrollmentUrl"/> is empty, ends in a slash or is not ASCII;
    /// or the SHA-256 digest of the <c>SubjectPublicKeyInfo</c> of <paramref name="csr"/> is not the
    /// <see cref="RenewalDecision.SubjectPublicKeyInfoSha256"/> of <paramref name="issuing"/>;
    /// or the issuer certificate has no subject key identifier, or its <c>notAfter</c> is not after the current second;
    /// or the issuer is outside the chain profile of CONTRACT.agent-identity.md §4:
    /// its certificate has neither a P-256 nor a P-384 key, no basicConstraints with cA set or no key usage with
    /// keyCertSign, or its generator does not sign with ecdsa-with-SHA256 for a P-256 key or ecdsa-with-SHA384 for a
    /// P-384 key, or holds another key than its certificate's.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="lifetime"/> is shorter than one second.
    /// </exception>
    public static X509Certificate2 Issue(
        RenewalDecision issuing,
        string enrollmentUrl,
        CertificateSigningRequest csr,
        IRootSigner issuer,
        TimeSpan lifetime,
        TimeProvider timeProvider,
        RandomNumberGenerator random)
    {
        ArgumentNullException.ThrowIfNull(issuing);

        if (issuing.Outcome != RenewalOutcome.IssuePendingCertificate)
        {
            throw new ArgumentException("The renewal decision does not issue a pending certificate.", nameof(issuing));
        }

        ArgumentNullException.ThrowIfNull(enrollmentUrl);

        // CONTRACT.agent-identity.md §4: the extension holds the token's `u`, which is ASCII, without trailing slashes.
        if (enrollmentUrl.Length == 0 || enrollmentUrl.EndsWith('/') || !Ascii.IsValid(enrollmentUrl))
        {
            throw new ArgumentException(
                "The enrollment URL is empty, ends in a slash or is not ASCII.",
                nameof(enrollmentUrl));
        }

        ThrowIfNotTheDecidedKey(csr, issuing.SubjectPublicKeyInfoSha256);

        // A decision to issue a pending certificate always carries the identity that it was made for.
        return Issue(issuing.Renewing!.IdentityId, enrollmentUrl, csr, issuer, lifetime, timeProvider, random);
    }

    // CONTRACT.agent-identity.md §2.1: every issued key is unique by SPKI SHA-256,
    // which the decision's key lookup checked for its own CSR key only.
    private static void ThrowIfNotTheDecidedKey(CertificateSigningRequest csr, ReadOnlyMemory<byte> decidedKey)
    {
        ArgumentNullException.ThrowIfNull(csr);

        if (!csr.SubjectPublicKeyInfoSha256.Span.SequenceEqual(decidedKey.Span))
        {
            throw new ArgumentException("The CSR key is not the key that the decision was made for.", nameof(csr));
        }
    }

    private static DateTimeOffset TruncateToSecond(DateTimeOffset value)
    {
        return new DateTimeOffset(value.UtcTicks - (value.UtcTicks % TimeSpan.TicksPerSecond), TimeSpan.Zero);
    }

    // RFC 5280 §4.1.2.2: a positive INTEGER of at most 20 octets.
    private static byte[] NewSerialNumber(RandomNumberGenerator random)
    {
        byte[] serialNumber = new byte[16];

        do
        {
            random.GetBytes(serialNumber);

            // A clear top bit keeps the INTEGER positive without a leading zero octet.
            serialNumber[0] &= 0x7F;
        }
        while (!serialNumber.AsSpan().ContainsAnyExcept((byte)0));

        return serialNumber;
    }
}
