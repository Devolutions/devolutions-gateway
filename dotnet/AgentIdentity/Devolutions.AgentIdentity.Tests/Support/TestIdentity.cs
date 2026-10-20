namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// Identities that the library authenticated, as a host receives them.
/// </summary>
internal static class TestIdentity
{
    /// <summary>
    /// Authenticates a request of <c>device-a</c> for an operation through the public API:
    /// <c>connect</c> through the channel handshake, the others as signed requests.
    /// </summary>
    public static async Task<AuthenticatedIdentity> AuthenticateAsync(AgentOperation operation)
    {
        TestAuthority authority = new(TestAuthority.DefaultNow);
        SignedHttpRequest request = authority.Valid(operation).ToHttpRequest();

        if (operation == AgentOperation.Connect)
        {
            ChannelOpeningResult opening = await authority.Authenticator.AuthenticateChannelOpeningAsync(
                request.Method,
                request.SignatureInput,
                request.Signature);
            Assert.True(opening.Succeeded, opening.FailureDetail);

            byte[] proof = TestChannelProof.Sign(
                TestVectors.Instance.Key("device-a"),
                opening.Opening.Challenge.Challenge.Challenge_.Span,
                TestRequest.DefaultNonce);
            ChannelHandshakeResult handshake =
                await opening.Opening.VerifyHelloAsync(VectorChannel.HelloMessage(opening.Opening, proof));
            Assert.True(handshake.Succeeded, handshake.FailureDetail);

            return handshake.Identity;
        }

        AuthenticationResult result = await authority.Authenticator.AuthenticateAsync(operation, request);
        Assert.True(result.Succeeded, result.FailureDetail);

        return result.Identity;
    }
}
