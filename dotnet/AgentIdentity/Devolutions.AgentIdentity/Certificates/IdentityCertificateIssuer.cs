using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity;

/// <summary>
/// Issues identity certificates, the leaf certificates through which agents authenticate.
/// </summary>
public static class IdentityCertificateIssuer
{
    // RFC 5280 §4.2.1.12: id-kp-clientAuth.
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    private const string SubjectKeyIdentifierOid = "2.5.29.14";

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
    /// and <paramref name="issuer"/> signs it with SHA-256.
    /// </para>
    /// <para>
    /// Taking the decision rather than an ID keeps the authority from certifying a key for an identity
    /// that no enrollment created.
    /// A renewal certifies a key for an existing identity,
    /// so it uses the overload that takes the identity that the renew request proved.
    /// </para>
    /// </remarks>
    /// <param name="creating">
    /// The decision of <see cref="EnrollmentRules.Decide"/> to create the identity,
    /// whose <see cref="EnrollmentDecision.Outcome"/> is <see cref="EnrollmentOutcome.CreateIdentity"/>.
    /// </param>
    /// <param name="csr">The validated CSR whose key the certificate is for.</param>
    /// <param name="issuer">The root that signs the certificate.</param>
    /// <param name="lifetime">The certificate lifetime, usually <see cref="DefaultLifetime"/>.</param>
    /// <param name="timeProvider">The clock, read once.</param>
    /// <param name="random">The source of the serial number.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="creating"/> does not create an identity;
    /// or the issuer certificate has no subject key identifier, or its <c>notAfter</c> is not after the current second.
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

        // A decision to create an identity always carries the ID minted for it.
        return Issue(creating.NewIdentityId!.Value, csr, issuer, lifetime, timeProvider, random);
    }

    // Private so that a certificate is issued only for an identity ID taken from a proof of that identity.
    private static X509Certificate2 Issue(
        Guid identityId,
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

        DateTimeOffset notBefore = TruncateToSecond(timeProvider.GetUtcNow());
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

        CertificateRequest request = new(subject.Build(), publicKey, HashAlgorithmName.SHA256);
        OidCollection usages = [new Oid(ClientAuthentication)];

        // RFC 5280 §4.2.1.2, method (1): the SHA-1 hash of the subjectPublicKey bits.
        X509SubjectKeyIdentifierHashAlgorithm keyIdMethod = X509SubjectKeyIdentifierHashAlgorithm.Sha1;
        Collection<X509Extension> extensions = request.CertificateExtensions;
        extensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        extensions.Add(new X509EnhancedKeyUsageExtension(usages, critical: false));
        extensions.Add(alternativeName.Build(critical: false));
        extensions.Add(new X509SubjectKeyIdentifierExtension(publicKey, keyIdMethod, critical: false));
        extensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerKeyId));

        return request.Create(
            issuerCertificate.SubjectName,
            issuer.SignatureGenerator,
            notBefore,
            notAfter,
            NewSerialNumber(random));
    }

    /// <summary>
    /// Issues the pending certificate of a renewal, for the identity that signed the renew request.
    /// </summary>
    /// <remarks>
    /// The certificate is the one that the other overload issues, with <see cref="AuthenticatedIdentity.IdentityId"/>
    /// as the identity ID.
    /// Taking the identity that the signature check produced, rather than an ID,
    /// keeps a renewal from certifying a key for an identity that a request only named.
    /// </remarks>
    /// <param name="renewing">
    /// The identity that a <c>renew</c> request proved, as <see cref="RequestAuthenticator.AuthenticateAsync"/>
    /// returns it for <see cref="AgentOperation.Renew"/>.
    /// </param>
    /// <param name="csr">The validated CSR whose key the certificate is for.</param>
    /// <param name="issuer">The root that signs the certificate.</param>
    /// <param name="lifetime">The certificate lifetime, usually <see cref="DefaultLifetime"/>.</param>
    /// <param name="timeProvider">The clock, read once.</param>
    /// <param name="random">The source of the serial number.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="renewing"/> was authenticated for another operation than <c>renew</c>;
    /// or the issuer certificate has no subject key identifier, or its <c>notAfter</c> is not after the current second.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="lifetime"/> is shorter than one second.
    /// </exception>
    public static X509Certificate2 Issue(
        AuthenticatedIdentity renewing,
        CertificateSigningRequest csr,
        IRootSigner issuer,
        TimeSpan lifetime,
        TimeProvider timeProvider,
        RandomNumberGenerator random)
    {
        ArgumentNullException.ThrowIfNull(renewing);

        if (renewing.Operation != AgentOperation.Renew)
        {
            throw new ArgumentException("The identity was not authenticated by a renew request.", nameof(renewing));
        }

        return Issue(renewing.IdentityId, csr, issuer, lifetime, timeProvider, random);
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
