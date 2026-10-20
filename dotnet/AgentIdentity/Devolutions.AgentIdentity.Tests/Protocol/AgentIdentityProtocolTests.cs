using System.Globalization;

namespace Devolutions.AgentIdentity.Tests;

public class AgentIdentityProtocolTests
{
    // CONTRACT.md §1: timestamps are RFC 3339 UTC strings ending in `Z`, such as 2026-09-24T12:00:00Z.
    // A timestamp names the whole second that contains the instant.
    [Theory]
    [InlineData("2026-09-24T12:00:00+00:00", "2026-09-24T12:00:00Z")]
    [InlineData("2026-09-24T14:00:00+02:00", "2026-09-24T12:00:00Z")]
    [InlineData("2026-09-24T23:30:00-01:00", "2026-09-25T00:30:00Z")]
    [InlineData("2026-09-24T12:00:00.9999999+00:00", "2026-09-24T12:00:00Z")]
    public void FormatTimestampWritesUtcWholeSeconds(string instant, string expected)
    {
        DateTimeOffset value = DateTimeOffset.Parse(instant, CultureInfo.InvariantCulture);

        Assert.Equal(expected, AgentIdentityProtocol.FormatTimestamp(value));
    }

    // A culture-sensitive format would write the Thai Buddhist year 2569 and the time separator of this culture.
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

    // CONTRACT.md §1: a thumbprint is base64url(SHA-256(certificate DER)).
    // The vector file gives the thumbprint of each certificate.
    [Theory]
    [MemberData(nameof(VectorData.KeyNames), MemberType = typeof(VectorData))]
    public void KeyCertificateHasTheVectorThumbprint(string name)
    {
        KeyVector key = TestVectors.Instance.Key(name);

        Assert.Equal(key.Thumbprint, AgentIdentityProtocol.ComputeThumbprint(key.Certificate));
    }

    [Fact]
    public void RootCertificateHasTheVectorThumbprint()
    {
        RootVector root = TestVectors.Instance.Root;

        Assert.Equal(root.Thumbprint, AgentIdentityProtocol.ComputeThumbprint(root.Certificate));
    }

    // CONTRACT.md §6: a request's `keyid` is the thumbprint of the certificate that signs it.
    [Theory]
    [MemberData(nameof(VectorData.RegisteredCertificateNames), MemberType = typeof(VectorData))]
    public void RegisteredCertificateHasTheVectorKeyId(string name)
    {
        RegisteredCertificateVector registered = TestVectors.Instance.HttpSignature.RegisteredCertificate(name);

        Assert.Equal(registered.KeyId, AgentIdentityProtocol.ComputeThumbprint(registered.Certificate));
    }

    // CONTRACT.md §5.4: servers accept request bodies up to 64 KiB.
    [Fact]
    public void MaxRequestBodyBytesIs64KiB()
    {
        Assert.Equal(65536, AgentIdentityProtocol.MaxRequestBodyBytes);
    }
}
