using System.Globalization;

namespace Devolutions.AgentIdentity.Tests;

public class AgentIdentityProtocolTests
{
    public static TheoryData<string> VectorCertificateNames => new(VectorCertificates.Select(vector => vector.Name));

    // Each certificate of the vector file, named by its path in the file.
    private static IEnumerable<(string Name, byte[] Certificate, string Thumbprint)> VectorCertificates =>
    [
        .. TestVectors.Instance.Keys.Select(key => ($"keys[{key.Name}]", key.Certificate, key.Thumbprint)),
        ("root", TestVectors.Instance.Root.Certificate, TestVectors.Instance.Root.Thumbprint),
        .. TestVectors.Instance.HttpSignature.Registered.Select(
            registered => ($"http_signature.registered[{registered.Name}]", registered.Certificate, registered.KeyId)),
    ];

    // CONTRACT.agent-identity.md §1: timestamps are RFC 3339 UTC strings ending in `Z`, such as 2026-09-24T12:00:00Z.
    // A timestamp names the whole second that contains the instant.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("2026-09-24T12:00:00+00:00", "2026-09-24T12:00:00Z")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("2026-09-24T14:00:00+02:00", "2026-09-24T12:00:00Z")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("2026-09-24T23:30:00-01:00", "2026-09-25T00:30:00Z")]
    // oracle: scaffold
    [InlineData("2026-09-24T12:00:00.9999999+00:00", "2026-09-24T12:00:00Z")]
    public void FormatTimestampWritesUtcWholeSeconds(string instant, string expected)
    {
        DateTimeOffset value = DateTimeOffset.Parse(instant, CultureInfo.InvariantCulture);

        Assert.Equal(expected, AgentIdentityProtocol.FormatTimestamp(value));
    }

    // RFC 3339 dates are Gregorian, and §5.6 writes them in ASCII digits with fixed separators, whatever the culture.
    // A culture-sensitive format would write the Thai Buddhist year 2569 and the time separator of this culture.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    // oracle: spec RFC 3339 §1
    // oracle: spec RFC 3339 §5.6
    [Fact]
    public void FormatTimestampIgnoresTheCurrentCulture()
    {
        CultureInfo culture = (CultureInfo)CultureInfo.GetCultureInfo("th-TH").Clone();
        culture.DateTimeFormat.TimeSeparator = ".";
        CultureInfo previous = CultureInfo.CurrentCulture;
        DateTimeOffset value = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

        try
        {
            CultureInfo.CurrentCulture = culture;

            Assert.Equal("2026-09-24T12:00:00Z", AgentIdentityProtocol.FormatTimestamp(value));
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    // CONTRACT.agent-identity.md §1: a thumbprint is base64url(SHA-256(certificate DER)).
    // CONTRACT.agent-identity.md §6: a request's `keyid` is the thumbprint of the certificate that signs it.
    // The vector file gives each certificate with its thumbprint, or a registered certificate with its keyid.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-signatures
    // oracle: reference docs/agent-identity/test-vectors.json
    [Theory]
    [MemberData(nameof(VectorCertificateNames))]
    public void CertificateHasTheVectorThumbprint(string name)
    {
        (_, byte[] certificate, string thumbprint) = VectorCertificates.Single(vector => vector.Name == name);

        Assert.Equal(thumbprint, AgentIdentityProtocol.ComputeThumbprint(certificate));
    }

    // Servers accept request bodies up to 64 KiB.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-identity-errors
    [Fact]
    public void MaxRequestBodyBytesIs64KiB()
    {
        Assert.Equal(65536, AgentIdentityProtocol.MaxRequestBodyBytes);
    }
}
