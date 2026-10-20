using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity;

/// <summary>
/// Authenticates the signed requests of agents, as CONTRACT.md §6 specifies.
/// </summary>
/// <remarks>
/// Each request goes through the six steps of CONTRACT.md §6 in order, and the first step that fails decides the error.
/// Exceptions from the certificate registry and the nonce store propagate to the caller.
/// </remarks>
public sealed class RequestAuthenticator
{
    // CONTRACT.md §6 step 3.
    private const long MaxSignatureLifetimeSeconds = 300;
    private const long ClockToleranceSeconds = 60;

    // CONTRACT.md §7.3 step 2.
    private const int ChallengeLength = 32;

    // RFC 5480 §2.1.1: id-ecPublicKey.
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    // CONTRACT.md §6 step 6, and the shared intent: a nonce is kept until 60 s after its signature expires.
    private static readonly TimeSpan NonceRetentionAfterExpiry = TimeSpan.FromSeconds(60);

    // RFC 5480 §2.1.1.1: the DER encoding of the namedCurve secp256r1, which is P-256.
    private static readonly byte[] P256CurveParameters = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    private readonly ICertificateRegistry _certificateRegistry;
    private readonly INonceStore _nonceStore;
    private readonly TimeProvider _timeProvider;
    private readonly RandomNumberGenerator _randomNumberGenerator;

    /// <summary>
    /// Creates an authenticator over the host's certificate registry and nonce store.
    /// </summary>
    /// <param name="certificateRegistry">The certificates that the authority issued.</param>
    /// <param name="nonceStore">The nonces of accepted signatures.</param>
    /// <param name="timeProvider">The authority's clock.</param>
    /// <param name="randomNumberGenerator">The source of the random bytes of each channel challenge.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public RequestAuthenticator(
        ICertificateRegistry certificateRegistry,
        INonceStore nonceStore,
        TimeProvider timeProvider,
        RandomNumberGenerator randomNumberGenerator)
    {
        ArgumentNullException.ThrowIfNull(certificateRegistry);
        ArgumentNullException.ThrowIfNull(nonceStore);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(randomNumberGenerator);

        _certificateRegistry = certificateRegistry;
        _nonceStore = nonceStore;
        _timeProvider = timeProvider;
        _randomNumberGenerator = randomNumberGenerator;
    }

    /// <summary>
    /// Authenticates a signed <c>renew</c>, <c>confirm</c> or <c>check-in</c> request.
    /// </summary>
    /// <remarks>
    /// A body larger than <see cref="AgentIdentityProtocol.MaxRequestBodyBytes"/> fails first,
    /// with <see cref="AgentIdentityError.BodyTooLarge"/>.
    /// The request then goes through the steps of CONTRACT.md §6,
    /// and its nonce is recorded only once every other step has passed.
    /// </remarks>
    /// <param name="operation">The operation of the endpoint that received the request.</param>
    /// <param name="request">The request, as received.</param>
    /// <param name="cancellationToken">A token that cancels the registry lookup and the nonce recording.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="operation"/> is <see cref="AgentOperation.Connect"/>,
    /// which <see cref="AuthenticateChannelOpeningAsync"/> authenticates, or is not a defined operation.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The registry returned a certificate with another thumbprint, or one whose key is not a P-256 key.
    /// </exception>
    public async ValueTask<AuthenticationResult> AuthenticateAsync(
        AgentOperation operation,
        SignedHttpRequest request,
        CancellationToken cancellationToken = default)
    {
        // A signed opening request never authenticates a stream on its own,
        // so only the channel handshake turns a verified opening into an identity.
        if (operation == AgentOperation.Connect)
        {
            throw new ArgumentOutOfRangeException(
                nameof(operation),
                operation,
                "A channel opening is authenticated by AuthenticateChannelOpeningAsync.");
        }

        SignedOperation signedOperation = SignedOperation.For(operation);
        ArgumentNullException.ThrowIfNull(request);

        if (request.Body.Length > AgentIdentityProtocol.MaxRequestBodyBytes)
        {
            return AuthenticationResult.Failure(
                AgentIdentityError.BodyTooLarge,
                "The request body is larger than 64 KiB.");
        }

        Verification verification = await VerifyAsync(
                signedOperation,
                request.Method,
                request.SignatureInput,
                request.Signature,
                request.ContentDigest,
                request.Body,
                cancellationToken)
            .ConfigureAwait(false);

        return verification.Accepted
            ? AuthenticationResult.Success(verification.Certificate.ToIdentity(operation))
            : AuthenticationResult.Failure(verification.Error, verification.FailureDetail);
    }

    /// <summary>
    /// Authenticates the signed opening request of an agent channel stream, and prepares the stream's challenge.
    /// </summary>
    /// <remarks>
    /// The opening request goes through the steps of CONTRACT.md §6 with tag <c>connect</c>,
    /// and its nonce is recorded only once every other step has passed.
    /// A verified opening does not authenticate the stream:
    /// the agent must still sign <see cref="ChannelOpening.Challenge"/>.
    /// </remarks>
    /// <param name="method">The request method, as received.</param>
    /// <param name="signatureInput">The <c>signature-input</c> metadata entries in received order.</param>
    /// <param name="signature">The <c>signature</c> metadata entries in received order.</param>
    /// <param name="cancellationToken">A token that cancels the registry lookup and the nonce recording.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">A metadata entry is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The registry returned a certificate with another thumbprint, or one whose key is not a P-256 key.
    /// </exception>
    public async ValueTask<ChannelOpeningResult> AuthenticateChannelOpeningAsync(
        string method,
        IReadOnlyList<string> signatureInput,
        IReadOnlyList<string> signature,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(method);
        string[] signatureInputLines = FieldLines.Copy(signatureInput, nameof(signatureInput));
        string[] signatureLines = FieldLines.Copy(signature, nameof(signature));

        Verification verification = await VerifyAsync(
                SignedOperation.Connect,
                method,
                signatureInputLines,
                signatureLines,
                [],
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);

        if (!verification.Accepted)
        {
            return ChannelOpeningResult.Failure(verification.Error, verification.FailureDetail);
        }

        byte[] challenge = new byte[ChallengeLength];
        _randomNumberGenerator.GetBytes(challenge);

        return ChannelOpeningResult.Success(
            new ChannelOpening(verification.Certificate, verification.Nonce, Guid.NewGuid(), challenge));
    }

    private async ValueTask<Verification> VerifyAsync(
        SignedOperation operation,
        string method,
        IReadOnlyList<string> signatureInput,
        IReadOnlyList<string> signature,
        IReadOnlyList<string> contentDigest,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        // Step 1.
        if (!SignatureFields.TryParse(
                operation,
                signatureInput,
                signature,
                contentDigest,
                out SignatureFields? fields,
                out string? failureDetail))
        {
            return Verification.Reject(AgentIdentityErrorCode.SignatureInvalid, failureDetail);
        }

        // Step 2.
        if (fields.Tag != operation.Tag)
        {
            return Verification.Reject(
                AgentIdentityErrorCode.SignatureInvalid,
                "Step 2: the tag is not the operation's tag.");
        }

        // Step 3.
        // Steps 3 and 4 compare against one reading of the clock, exactly, so that they agree on what now is.
        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (!IsWithinWindow(fields.Created, fields.Expires, now))
        {
            return Verification.Reject(
                AgentIdentityErrorCode.ClockSkew,
                "Step 3: created and expires are outside the accepted window.");
        }

        // Step 4.
        RegisteredCertificate? registered = await _certificateRegistry
            .FindByThumbprintAsync(fields.KeyId, cancellationToken)
            .ConfigureAwait(false);

        if (registered is null)
        {
            return Verification.Reject(
                AgentIdentityErrorCode.IdentityUnknown,
                "Step 4: no certificate is registered with the keyid, or its identity was deleted.");
        }

        using X509Certificate2 certificate = LoadRegisteredCertificate(fields.KeyId, registered);

        if (registered.Status is not (CertificateStatus.Pending or CertificateStatus.Current))
        {
            return Verification.Reject(AgentIdentityErrorCode.IdentityUnknown, "Step 4: the certificate is retired.");
        }

        if (registered.IdentityRevoked)
        {
            return Verification.Reject(AgentIdentityErrorCode.IdentityRevoked, "Step 4: the identity is revoked.");
        }

        DateTimeOffset notBefore = new(certificate.NotBefore.ToUniversalTime());
        DateTimeOffset notAfter = new(certificate.NotAfter.ToUniversalTime());

        if (!operation.AcceptsValidity(notBefore, notAfter, now))
        {
            return Verification.Reject(
                AgentIdentityErrorCode.CertificateExpired,
                operation.HasRenewalGrace
                    ? "Step 4: the certificate is expired beyond its renewal grace."
                    : "Step 4: the certificate is expired.");
        }

        // Step 5.
        // UNTESTED: the digest comparison takes the same time whichever bytes differ.
        // The digest is not secret, but a constant-time comparison needs no argument that its timing reveals nothing.
        // When changing this check, keep CryptographicOperations.FixedTimeEquals.
        if (fields.ContentDigest is { } digest
            && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(body.Span), digest))
        {
            return Verification.Reject(
                AgentIdentityErrorCode.SignatureInvalid,
                "Step 5: Content-Digest does not match the body.");
        }

        if (!fields.TryBuildSignatureBase(method, out byte[]? signatureBase))
        {
            return Verification.Reject(
                AgentIdentityErrorCode.SignatureInvalid,
                "Step 5: the method is not an HTTP token, so the signature base has no @method.");
        }

        using ECDsa publicKey = LoadPublicKey(certificate);

        if (!EcdsaP256Signature.Verify(publicKey, signatureBase, fields.Signature))
        {
            return Verification.Reject(
                AgentIdentityErrorCode.SignatureInvalid,
                "Step 5: the signature does not verify.");
        }

        // Step 6.
        DateTimeOffset retainUntil = DateTimeOffset.FromUnixTimeSeconds(fields.Expires) + NonceRetentionAfterExpiry;
        bool recorded = await _nonceStore
            .TryRecordAsync(fields.KeyId, fields.Nonce, retainUntil, cancellationToken)
            .ConfigureAwait(false);

        if (!recorded)
        {
            return Verification.Reject(
                AgentIdentityErrorCode.SignatureInvalid,
                "Step 6: the nonce was already accepted with the keyid.");
        }

        VerifiedCertificate verified = new(
            registered.IdentityId,
            fields.KeyId,
            registered.Status,
            notBefore,
            notAfter,
            publicKey.ExportSubjectPublicKeyInfo());

        return Verification.Accept(verified, fields.Nonce);
    }

    // CONTRACT.md §6 step 3: 0 < expires − created ≤ 300, created ≤ now + 60 and expires ≥ now − 60.
    private static bool IsWithinWindow(long created, long expires, DateTimeOffset now)
    {
        // Both are integers of at most 15 digits, so their difference fits in a long.
        long lifetime = expires - created;
        if (lifetime is <= 0 or > MaxSignatureLifetimeSeconds)
        {
            return false;
        }

        // Ticks in 128 bits keep the comparison exact, for times outside the range of DateTimeOffset too.
        Int128 nowTicks = (now - DateTimeOffset.UnixEpoch).Ticks;
        Int128 toleranceTicks = (Int128)ClockToleranceSeconds * TimeSpan.TicksPerSecond;

        return (Int128)created * TimeSpan.TicksPerSecond <= nowTicks + toleranceTicks
            && (Int128)expires * TimeSpan.TicksPerSecond >= nowTicks - toleranceTicks;
    }

    // The registry answers a thumbprint with a certificate that the authority issued, so anything else is a host bug,
    // which fails as a server error rather than as a verdict on the agent.
    private static X509Certificate2 LoadRegisteredCertificate(string keyId, RegisteredCertificate registered)
    {
        ReadOnlySpan<byte> der = registered.CertificateDer.Span;

        if (AgentIdentityProtocol.ComputeThumbprint(der) != keyId)
        {
            throw new InvalidOperationException(
                "The certificate registry returned a certificate whose thumbprint is not the keyid it was asked for.");
        }

        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(der);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                "The certificate registry returned bytes that are not an X.509 certificate.",
                exception);
        }

        PublicKey publicKey = certificate.PublicKey;
        byte[]? curve = publicKey.EncodedParameters?.RawData;
        if (publicKey.Oid.Value != EcPublicKeyOid
            || curve is null
            || !curve.AsSpan().SequenceEqual(P256CurveParameters))
        {
            certificate.Dispose();
            throw new InvalidOperationException(
                "The certificate registry returned a certificate whose key is not a P-256 key.");
        }

        return certificate;
    }

    private static ECDsa LoadPublicKey(X509Certificate2 certificate)
    {
        try
        {
            return certificate.GetECDsaPublicKey()
                ?? throw new InvalidOperationException(
                    "The certificate registry returned a certificate whose key is not an EC key.");
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                "The certificate registry returned a certificate whose P-256 key cannot be loaded.",
                exception);
        }
    }

    /// <summary>
    /// The outcome of the steps of CONTRACT.md §6: the verified certificate and nonce, or the error of the failed step.
    /// </summary>
    private sealed class Verification
    {
        [MemberNotNullWhen(true, nameof(Certificate), nameof(Nonce))]
        [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
        public bool Accepted { get; private init; }

        public VerifiedCertificate? Certificate { get; private init; }

        public string? Nonce { get; private init; }

        public AgentIdentityError? Error { get; private init; }

        public string? FailureDetail { get; private init; }

        public static Verification Accept(VerifiedCertificate certificate, string nonce)
        {
            return new Verification { Accepted = true, Certificate = certificate, Nonce = nonce };
        }

        public static Verification Reject(AgentIdentityErrorCode code, string failureDetail)
        {
            return new Verification { Error = AgentIdentityError.From(code), FailureDetail = failureDetail };
        }
    }
}
