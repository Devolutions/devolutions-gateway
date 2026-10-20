using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The bodies of the successful responses of CONTRACT.md §5, each parsed with the BCL and checked against the contract.
/// </summary>
public class ResponseBodiesTests
{
    // CONTRACT.md §1: IDs are lowercase hyphenated UUIDs; these have hexadecimal letters, so their case shows.
    // The identity is device-a of the vector file, whose certificate the vector root issued.
    private const string AuthorityIdText = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    private const string IdentityIdText = "0b3c6a52-7a38-4f55-9a1c-2f1a8d3c9e01";

    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    private static readonly Guid AuthorityId = Guid.Parse(AuthorityIdText.ToUpperInvariant());
    private static readonly Guid IdentityId = Guid.Parse(IdentityIdText.ToUpperInvariant());

    private static readonly X509Certificate2 VectorRoot =
        X509CertificateLoader.LoadCertificate(TestVectors.Instance.Root.Certificate);

    private static readonly X509Certificate2 DeviceA =
        X509CertificateLoader.LoadCertificate(TestVectors.Instance.Key("device-a").Certificate);

    private static readonly IdentityConfig Config = IdentityConfig.Create(
        7,
        "https://host/dvls",
        [new("psu_channel_url", TestJson.Parse("\"https://psu/channel\""))]);

    // The bodies that carry a certificate chain, written for a given chain.
    private static readonly Dictionary<string, Func<IEnumerable<X509Certificate2>, byte[]>> ChainBodies = new()
    {
        ["enroll"] = chain => ResponseBodies.Enroll(AuthorityId, IdentityId, chain, Config),
        ["renew"] = ResponseBodies.Renew,
    };

    // The bodies that carry a config, written for a given config.
    private static readonly Dictionary<string, Func<IdentityConfig, byte[]>> ConfigBodies = new()
    {
        ["enroll"] = config => ResponseBodies.Enroll(AuthorityId, IdentityId, [DeviceA, VectorRoot], config),
        ["check-in"] = config => ResponseBodies.CheckIn(config, renewalRequested: false),
    };

    public static TheoryData<string> ChainBodyNames => new(ChainBodies.Keys);

    public static TheoryData<string> ConfigBodyNames => new(ConfigBodies.Keys);

    // CONTRACT.md §5.1: each root has `certificate`, `thumbprint`, `not_before` and `not_after`, all strings.
    [Fact]
    public void TrustAnchorRootHasExactlyTheContractMembers()
    {
        byte[] body = ResponseBodies.TrustAnchor([VectorRoot]);

        Dictionary<string, JsonElement> members = TestJson.Members(body);
        Assert.Equal(["roots"], TestJson.Names(members));
        Dictionary<string, JsonElement> root = TestJson.Members(Assert.Single(TestJson.Elements(members["roots"])));
        Assert.Equal(["certificate", "not_after", "not_before", "thumbprint"], TestJson.Names(root));
        Assert.All(root.Values, value => Assert.Equal(JsonValueKind.String, value.ValueKind));
    }

    // CONTRACT.md §1: a certificate is its DER in canonical base64, and its thumbprint is base64url(SHA-256(DER)),
    // which the vector file gives for its root.
    [Fact]
    public void TrustAnchorGivesTheDerAndThumbprintOfTheRoot()
    {
        byte[] body = ResponseBodies.TrustAnchor([VectorRoot]);

        Dictionary<string, JsonElement> root = TestJson.Members(Roots(body)[0]);
        Assert.Equal(TestVectors.Instance.Root.Certificate, TestJson.CanonicalBase64(root["certificate"]));
        Assert.Equal(TestVectors.Instance.Root.Thumbprint, root["thumbprint"].GetString());
    }

    // CONTRACT.md §1: timestamps are RFC 3339 UTC strings ending in `Z`.
    // The validity is given here in offsets other than UTC, and the test machine's own time zone may be another.
    [Fact]
    public void TrustAnchorGivesTheValidityOfTheRootInUtc()
    {
        using X509Certificate2 root = SelfSignedRoot(
            new DateTimeOffset(2026, 1, 2, 12, 4, 5, TimeSpan.FromHours(9)),
            new DateTimeOffset(2036, 7, 8, 9, 10, 11, TimeSpan.FromHours(-4)));

        byte[] body = ResponseBodies.TrustAnchor([root]);

        Dictionary<string, JsonElement> entry = TestJson.Members(Roots(body)[0]);
        Assert.Equal("2026-01-02T03:04:05Z", entry["not_before"].GetString());
        Assert.Equal("2036-07-08T13:10:11Z", entry["not_after"].GetString());
    }

    // CONTRACT.md §5.1: the response lists one root normally and two during a rotation.
    [Fact]
    public void TrustAnchorListsEveryRootInTheOrderGiven()
    {
        using X509Certificate2 newRoot = SelfSignedRoot(Now.AddDays(-1), Now.AddYears(10));

        byte[] body = ResponseBodies.TrustAnchor([VectorRoot, newRoot]);

        JsonElement[] roots = Roots(body);
        Assert.Equal(
            [VectorRoot.RawData, newRoot.RawData],
            roots.Select(root => TestJson.CanonicalBase64(TestJson.Members(root)["certificate"])));
    }

    // CONTRACT.md §5.1: the response always lists a root, and two during a rotation.
    [Fact]
    public void TrustAnchorRejectsNoRoots()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() => ResponseBodies.TrustAnchor([]));

        Assert.Equal("roots", exception.ParamName);
    }

    [Fact]
    public void TrustAnchorRejectsANullRoot()
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => ResponseBodies.TrustAnchor([VectorRoot, null!]));

        Assert.Equal("roots", exception.ParamName);
    }

    // CONTRACT.md §5.2: `authority_id`, `identity_id`, `certificate_chain` and `config`, every one of them required.
    // §1: IDs are lowercase hyphenated UUIDs.
    [Fact]
    public void EnrollHasExactlyTheContractMembers()
    {
        byte[] body = ResponseBodies.Enroll(AuthorityId, IdentityId, [DeviceA, VectorRoot], Config);

        Dictionary<string, JsonElement> members = TestJson.Members(body);
        Assert.Equal(["authority_id", "certificate_chain", "config", "identity_id"], TestJson.Names(members));
        Assert.Equal(JsonValueKind.String, members["authority_id"].ValueKind);
        Assert.Equal(AuthorityIdText, members["authority_id"].GetString());
        Assert.Equal(JsonValueKind.String, members["identity_id"].ValueKind);
        Assert.Equal(IdentityIdText, members["identity_id"].GetString());
        Assert.Equal(JsonValueKind.Array, members["certificate_chain"].ValueKind);
        Assert.Equal(JsonValueKind.Object, members["config"].ValueKind);
    }

    // RFC 9562 §5.9: the nil UUID stands for the absence of a UUID, and CONTRACT.md §5.2 requires both IDs.
    [Fact]
    public void EnrollRejectsTheNilAuthorityId()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => ResponseBodies.Enroll(Guid.Empty, IdentityId, [DeviceA, VectorRoot], Config));

        Assert.Equal("authorityId", exception.ParamName);
    }

    [Fact]
    public void EnrollRejectsTheNilIdentityId()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => ResponseBodies.Enroll(AuthorityId, Guid.Empty, [DeviceA, VectorRoot], Config));

        Assert.Equal("identityId", exception.ParamName);
    }

    // CONTRACT.md §5.3: `200`: `{ "certificate_chain": [ ... ] }`.
    [Fact]
    public void RenewHasExactlyTheContractMembers()
    {
        byte[] body = ResponseBodies.Renew([DeviceA, VectorRoot]);

        Dictionary<string, JsonElement> members = TestJson.Members(body);
        Assert.Equal(["certificate_chain"], TestJson.Names(members));
        Assert.Equal(JsonValueKind.Array, members["certificate_chain"].ValueKind);
    }

    // CONTRACT.md §5.6: `config` and `renewal_requested`, the identity's request-renewal flag as a JSON boolean.
    [Theory]
    [InlineData(true, JsonValueKind.True)]
    [InlineData(false, JsonValueKind.False)]
    public void CheckInHasExactlyTheContractMembers(bool renewalRequested, JsonValueKind expected)
    {
        byte[] body = ResponseBodies.CheckIn(Config, renewalRequested);

        Dictionary<string, JsonElement> members = TestJson.Members(body);
        Assert.Equal(["config", "renewal_requested"], TestJson.Names(members));
        Assert.Equal(JsonValueKind.Object, members["config"].ValueKind);
        Assert.Equal(expected, members["renewal_requested"].ValueKind);
    }

    // CONTRACT.md §4: chains are leaf-first; §1: each certificate is its DER in canonical base64.
    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void ChainIsWrittenLeafFirst(string endpoint)
    {
        byte[] body = ChainBodies[endpoint]([DeviceA, VectorRoot]);

        JsonElement[] chain = Chain(body);
        Assert.Equal(
            [TestVectors.Instance.Key("device-a").Certificate, TestVectors.Instance.Root.Certificate],
            chain.Select(TestJson.CanonicalBase64));
    }

    // CONTRACT.md §4: a chain has any length, so the leaf alone is a chain too.
    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void ChainOfTheLeafAloneIsWritten(string endpoint)
    {
        byte[] body = ChainBodies[endpoint]([DeviceA]);

        JsonElement[] chain = Chain(body);
        Assert.Equal([TestVectors.Instance.Key("device-a").Certificate], chain.Select(TestJson.CanonicalBase64));
    }

    // RFC 5280 §4.1.2.6: a CA's subject is encoded exactly as the issuer of each certificate it issues,
    // so in a leaf-first chain the issuer of each certificate is the subject of the next.
    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void ChainWithTheRootFirstIsRejected(string endpoint)
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => ChainBodies[endpoint]([VectorRoot, DeviceA]));

        Assert.Equal("certificateChain", exception.ParamName);
    }

    // The other root has another subject than the vector root, which issued the leaf.
    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void ChainWithACertificateThatDidNotIssueThePreviousOneIsRejected(string endpoint)
    {
        using X509Certificate2 otherRoot = SelfSignedRoot(Now.AddDays(-1), Now.AddYears(10));

        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => ChainBodies[endpoint]([DeviceA, otherRoot]));

        Assert.Equal("certificateChain", exception.ParamName);
    }

    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void EmptyChainIsRejected(string endpoint)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() => ChainBodies[endpoint]([]));

        Assert.Equal("certificateChain", exception.ParamName);
    }

    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void ChainWithANullCertificateIsRejected(string endpoint)
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => ChainBodies[endpoint]([DeviceA, null!]));

        Assert.Equal("certificateChain", exception.ParamName);
    }

    // A writer that read the chain twice could check one chain and write another.
    [Theory]
    [MemberData(nameof(ChainBodyNames))]
    public void ChainIsReadOnce(string endpoint)
    {
        int reads = 0;

        IEnumerable<X509Certificate2> ReadChain()
        {
            reads++;
            yield return DeviceA;
            yield return VectorRoot;
        }

        ChainBodies[endpoint](ReadChain());

        Assert.Equal(1, reads);
    }

    [Fact]
    public void TrustAnchorReadsTheRootsOnce()
    {
        int reads = 0;

        IEnumerable<X509Certificate2> ReadRoots()
        {
            reads++;
            yield return VectorRoot;
        }

        ResponseBodies.TrustAnchor(ReadRoots());

        Assert.Equal(1, reads);
    }

    // CONTRACT.md §5.2 and §5.6: `config` is the identity's config, in the shape of §5.2.
    [Theory]
    [MemberData(nameof(ConfigBodyNames))]
    public void BodyCarriesTheConfig(string endpoint)
    {
        byte[] body = ConfigBodies[endpoint](Config);

        Dictionary<string, JsonElement> config = TestJson.Members(TestJson.Members(body)["config"]);
        Assert.Equal(["agent_channel_url", "psu_channel_url", "revision", "version"], TestJson.Names(config));
        Assert.Equal("1", config["version"].GetRawText());
        Assert.Equal("7", config["revision"].GetRawText());
        Assert.Equal("https://host/dvls", config["agent_channel_url"].GetString());
        Assert.Equal("https://psu/channel", config["psu_channel_url"].GetString());
    }

    private static JsonElement[] Roots(byte[] body)
    {
        return TestJson.Elements(TestJson.Members(body)["roots"]);
    }

    private static JsonElement[] Chain(byte[] body)
    {
        return TestJson.Elements(TestJson.Members(body)["certificate_chain"]);
    }

    private static X509Certificate2 SelfSignedRoot(DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=Test Agent Identity Root 2", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        return request.CreateSelfSigned(notBefore, notAfter);
    }
}
