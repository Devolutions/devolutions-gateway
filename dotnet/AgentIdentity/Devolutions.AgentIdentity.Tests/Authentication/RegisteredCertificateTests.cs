namespace Devolutions.AgentIdentity.Tests;

public class RegisteredCertificateTests
{
    // An undefined status from the host's storage must fail as a host bug,
    // rather than draw identity_unknown, which ends the identity for the agent.
    // The default is the value of an uninitialized status, and 4 follows the last of the three statuses.
    // CONTRACT.agent-identity.md Definitions: a certificate is pending, current or retired;
    // §5.4: identity_unknown is terminal.
    // Framework Design Guidelines, Parameter Design: validate enum parameters, since an enum may hold any integer.
    [Theory]
    [InlineData(default(CertificateStatus))]
    [InlineData((CertificateStatus)4)]
    public void RefusesAnUndefinedStatus(CertificateStatus undefined)
    {
        KeyVector key = TestVectors.Instance.Key("device-a");

        Assert.Throws<ArgumentOutOfRangeException>(
            () => new RegisteredCertificate(key.IdentityId, key.Certificate, undefined, identityRevoked: false));
    }
}
