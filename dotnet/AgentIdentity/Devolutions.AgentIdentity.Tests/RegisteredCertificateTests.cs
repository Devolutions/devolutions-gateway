namespace Devolutions.AgentIdentity.Tests;

public class RegisteredCertificateTests
{
    // An undefined status from the host's storage must fail as a host bug,
    // rather than draw identity_unknown, which ends the identity for the agent.
    [Fact]
    public void RefusesAnUndefinedStatus()
    {
        KeyVector key = TestVectors.Instance.Key("device-a");
        CertificateStatus undefined = (CertificateStatus)3;

        Assert.Throws<ArgumentOutOfRangeException>(
            () => new RegisteredCertificate(key.IdentityId, key.Certificate, undefined, identityRevoked: false));
    }
}
