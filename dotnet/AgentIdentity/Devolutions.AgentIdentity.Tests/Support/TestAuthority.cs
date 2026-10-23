using Devolutions.Agent.Channel.V1;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// An authority for tests that sign their own requests:
/// every vector key is registered, current and not revoked, unless a test registers it otherwise.
/// </summary>
internal sealed class TestAuthority
{
    public TestAuthority(DateTimeOffset now, RecordingNonceStore? nonces = null, TimeProvider? clock = null)
    {
        Now = now;
        Nonces = nonces ?? new RecordingNonceStore();

        foreach (KeyVector key in TestVectors.Instance.Keys)
        {
            Registry.Register(key);
        }

        Authenticator = new RequestAuthenticator(Registry, Nonces, clock ?? new FixedTimeProvider(now), Random);
    }

    /// <summary>
    /// An instant within the validity of the certificate of <c>device-a</c>,
    /// as <c>http_signature.registered</c> gives it.
    /// </summary>
    public static DateTimeOffset DefaultNow { get; } = DateTimeOffset.FromUnixTimeSeconds(1_790_000_000);

    public DateTimeOffset Now { get; }

    public FakeCertificateRegistry Registry { get; } = new();

    public RecordingNonceStore Nonces { get; }

    public CountingRandomNumberGenerator Random { get; } = new();

    public RequestAuthenticator Authenticator { get; }

    public TestRequest Valid(AgentOperation operation, KeyVector? key = null, string nonce = TestRequest.DefaultNonce)
    {
        return TestRequest.Valid(operation, Now, key, nonce);
    }

    public Task<string> OutcomeAsync(TestRequest request)
    {
        return OutcomeAsync(request.Operation, request.ToHttpRequest());
    }

    /// <summary>
    /// Authenticates a request through the public API:
    /// <c>connect</c> as a channel opening, the others as signed requests.
    /// </summary>
    /// <returns><c>ok</c> or the wire value of the error code, as the vector file writes outcomes.</returns>
    public async Task<string> OutcomeAsync(AgentOperation operation, SignedHttpRequest request)
    {
        if (operation == AgentOperation.Connect)
        {
            ChannelOpeningResult opening = await AuthenticateChannelOpeningAsync(request);

            return opening.Succeeded ? "ok" : opening.Error.Code.ToWireValue();
        }

        AuthenticationResult result = await Authenticator.AuthenticateAsync(operation, request);

        return result.Succeeded ? "ok" : result.Error.Code.ToWireValue();
    }

    /// <summary>
    /// Opens a channel through the public API with a valid <c>connect</c> request of <c>device-a</c>.
    /// </summary>
    public async Task<ChannelOpening> OpenChannelAsync(string nonce = TestRequest.DefaultNonce)
    {
        ChannelOpeningResult result =
            await AuthenticateChannelOpeningAsync(Valid(AgentOperation.Connect, nonce: nonce).ToHttpRequest());

        Assert.True(result.Succeeded, result.FailureDetail);
        return result.Opening;
    }

    /// <summary>
    /// A <c>Hello</c> of <c>device-a</c> that answers the Challenge of an opening of <c>device-a</c>.
    /// </summary>
    public static AgentMessage ValidHello(ChannelOpening opening)
    {
        byte[] proof = TestChannelProof.Sign(
            TestVectors.Instance.Key("device-a"),
            opening.Challenge.Challenge.Challenge_.Span,
            opening.ConnectNonce);

        return VectorChannel.HelloMessage(opening, proof);
    }

    private ValueTask<ChannelOpeningResult> AuthenticateChannelOpeningAsync(SignedHttpRequest request)
    {
        return Authenticator.AuthenticateChannelOpeningAsync(request.Method, request.SignatureInput, request.Signature);
    }
}
