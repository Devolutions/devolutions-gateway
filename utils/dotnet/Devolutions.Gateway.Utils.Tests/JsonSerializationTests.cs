using System.Text.Json;

namespace Devolutions.Gateway.Utils.Tests;

public class JsonSerialization
{
    static readonly Guid gatewayId = new Guid("ccbaad3f-4627-4666-8bb5-cb6a1a7db815");
    static readonly Guid sessionId = new Guid("3e7c1854-f1eb-42d2-b9cb-9303036e50da");

    [Fact]
    public void KdcClaims()
    {
        const string EXPECTED = """{"krb_kdc":"tcp://hello.world:88","krb_realm":"my.realm.com","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new KdcClaims(gatewayId, "tcp://hello.world:88", "MY.REALM.COM");
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void JmuxClaims()
    {
        const string EXPECTED = """{"dst_hst":"tcp://hello.world","jet_ap":"rdp","jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new JmuxClaims(gatewayId, "hello.world", ApplicationProtocol.Rdp, sessionId);
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void JmuxClaimsWithAdditionalDestinations()
    {
        const string EXPECTED = """{"dst_hst":"tcp://hello.world","dst_addl":["udp://farewell","tcp://and-yet-another-one"],"jet_ap":"rdp","jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new JmuxClaims(gatewayId, "hello.world", ApplicationProtocol.Rdp, sessionId);
        claims.AdditionalDestinations = new List<TargetAddr> { "udp://farewell", "and-yet-another-one" };
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void JmuxClaimsHttpExpanded()
    {
        const string EXPECTED = """{"dst_hst":"http://hello.world:80","dst_addl":["https://hello.world:443","http://www.hello.world:80","https://www.hello.world:443"],"jet_ap":"http","jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new JmuxClaims(gatewayId, "http://hello.world", ApplicationProtocol.Http, sessionId);
        claims.HttpExpandAdditionals();
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void JmuxClaimsHttpsExpanded()
    {
        const string EXPECTED = """{"dst_hst":"https://hello.world:443","dst_addl":["udp://farewell","tcp://and-yet-another-one","https://www.hello.world:443"],"jet_ap":"https","jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new JmuxClaims(gatewayId, "https://hello.world", ApplicationProtocol.Https, sessionId);
        claims.AdditionalDestinations = new List<TargetAddr> { "udp://farewell", "and-yet-another-one" };
        claims.HttpExpandAdditionals();
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void AssociationClaims()
    {
        const string EXPECTED = """{"dst_hst":"tcp://hello.world","jet_ap":"rdp","jet_cm":"fwd","jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new AssociationClaims(gatewayId, "hello.world", ApplicationProtocol.Rdp, sessionId);
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void AssociationClaimsWithAlternateDestinations()
    {
        const string EXPECTED = """{"dst_hst":"tcp://hello.world","dst_alt":["tcp://another-host:4222"],"jet_ap":"rdp","jet_cm":"fwd","jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new AssociationClaims(gatewayId, "hello.world", ApplicationProtocol.Rdp, sessionId);
        claims.AlternateDestinations = new List<TargetAddr> { "another-host:4222" };
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void ScopeClaims()
    {
        const string EXPECTED = """{"scope":"*","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new ScopeClaims(gatewayId, AccessScope.Star);
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void JrlClaims()
    {
        const string EXPECTED = """{"jrl":["2dd6fb87-5340-4a85-9e96-d383ebef8a41","01f2b129-bfbf-44fb-8b6e-5cbaf7a71300"],"jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        IEnumerable<Guid> revokedTokenList = new List<Guid>() { Guid.Parse("2dd6fb87-5340-4a85-9e96-d383ebef8a41"), Guid.Parse("01f2b129-bfbf-44fb-8b6e-5cbaf7a71300") };
        var claims = new JrlClaims(gatewayId, revokedTokenList);
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

    [Fact]
    public void RecordingClaims()
    {
        const string EXPECTED = """{"jet_aid":"3e7c1854-f1eb-42d2-b9cb-9303036e50da","jet_rop":"push","jet_gw_id":"ccbaad3f-4627-4666-8bb5-cb6a1a7db815"}""";

        var claims = new RecordingClaims(gatewayId, sessionId, RecordingOperation.Push);
        string result = JsonSerializer.Serialize(claims);
        Assert.Equal(EXPECTED, result);
    }

}