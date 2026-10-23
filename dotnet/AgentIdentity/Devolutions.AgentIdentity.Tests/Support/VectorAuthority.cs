namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The authority that <c>http_signature</c> describes: its registered certificates, an empty nonce store,
/// and a clock that each case sets to its <c>now</c>.
/// </summary>
internal sealed class VectorAuthority
{
    public VectorAuthority()
    {
        foreach (RegisteredCertificateVector registered in TestVectors.Instance.HttpSignature.Registered)
        {
            Registry.Register(
                registered.KeyId,
                new RegisteredCertificate(
                    registered.IdentityId,
                    registered.Certificate,
                    Status(registered.CertificateStatus),
                    registered.IdentityRevoked));
        }

        Authenticator = new RequestAuthenticator(Registry, Nonces, Clock, Random);
    }

    public FakeCertificateRegistry Registry { get; } = new();

    public RecordingNonceStore Nonces { get; } = new();

    public FixedTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch);

    public CountingRandomNumberGenerator Random { get; } = new();

    public RequestAuthenticator Authenticator { get; }

    /// <summary>
    /// Runs a case through the public API: <c>connect</c> as a channel opening, the others as signed requests.
    /// </summary>
    public async Task<VectorOutcome> RunAsync(HttpSignatureCaseVector vector)
    {
        Clock.Now = vector.Now;

        if (vector.Endpoint == "connect")
        {
            ChannelOpeningResult opening = await OpenChannelAsync(Authenticator, vector);

            return opening.Succeeded
                ? VectorOutcome.Ok
                : new VectorOutcome(opening.Error.Code.ToWireValue(), opening.FailureDetail);
        }

        SignedHttpRequest request = new(
            vector.Method,
            Lines(vector.Headers.SignatureInput),
            Lines(vector.Headers.Signature),
            Lines(vector.Headers.ContentDigest),
            vector.BodyBytes);
        AuthenticationResult result = await Authenticator.AuthenticateAsync(Operation(vector.Endpoint), request);

        return result.Succeeded
            ? VectorOutcome.Ok
            : new VectorOutcome(result.Error.Code.ToWireValue(), result.FailureDetail);
    }

    /// <summary>
    /// Authenticates the opening request of a <c>connect</c> case through the public API.
    /// </summary>
    public static ValueTask<ChannelOpeningResult> OpenChannelAsync(
        RequestAuthenticator authenticator,
        HttpSignatureCaseVector vector)
    {
        return authenticator.AuthenticateChannelOpeningAsync(
            vector.Method,
            Lines(vector.Headers.SignatureInput),
            Lines(vector.Headers.Signature));
    }

    /// <summary>
    /// The field lines of a vector header, which holds at most one.
    /// </summary>
    public static string[] Lines(string? header)
    {
        return header is null ? [] : [header];
    }

    // CONTRACT.agent-identity.md §5: each endpoint is one operation.
    public static AgentOperation Operation(string endpoint)
    {
        return endpoint switch
        {
            "renew" => AgentOperation.Renew,
            "confirm" => AgentOperation.Confirm,
            "check-in" => AgentOperation.CheckIn,
            "connect" => AgentOperation.Connect,
            _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, "Not an endpoint of the vectors."),
        };
    }

    // CONTRACT.agent-identity.md "Definitions": the certificate statuses.
    private static CertificateStatus Status(string status)
    {
        return status switch
        {
            "pending" => CertificateStatus.Pending,
            "current" => CertificateStatus.Current,
            "retired" => CertificateStatus.Retired,
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Not a certificate status."),
        };
    }
}

/// <param name="Outcome"><c>ok</c> or the wire value of the error code, as the vector file writes outcomes.</param>
/// <param name="FailureDetail">The failure detail, when the request failed.</param>
internal sealed record VectorOutcome(string Outcome, string? FailureDetail)
{
    public static VectorOutcome Ok { get; } = new("ok", null);
}
