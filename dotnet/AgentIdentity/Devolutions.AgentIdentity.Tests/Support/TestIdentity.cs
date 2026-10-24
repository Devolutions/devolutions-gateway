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

        if (operation == AgentOperation.Connect)
        {
            ChannelOpening opening = await authority.OpenChannelAsync();
            ChannelHandshakeResult handshake = await opening.VerifyHelloAsync(TestAuthority.ValidHello(opening));
            Assert.True(handshake.Succeeded, handshake.FailureDetail);

            return handshake.Identity;
        }

        SignedHttpRequest request = authority.Valid(operation).ToHttpRequest();
        AuthenticationResult result = await authority.Authenticator.AuthenticateAsync(operation, request);
        Assert.True(result.Succeeded, result.FailureDetail);

        return result.Identity;
    }
}
