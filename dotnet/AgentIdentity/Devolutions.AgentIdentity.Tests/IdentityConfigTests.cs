using System.Text.Json;

namespace Devolutions.AgentIdentity.Tests;

public class IdentityConfigTests
{
    // CONTRACT.md §5.2: `config` holds `version`, which is 1, `revision` and `agent_channel_url`.
    // An agent reads both numbers as integers, so 1.0 or 3e0 would not do.
    [Fact]
    public void JsonHasTheContractMembers()
    {
        IdentityConfig config = IdentityConfig.Create(3, "https://host/dvls");

        Dictionary<string, JsonElement> members = TestJson.Members(config.ToUtf8Json());

        Assert.Equal(["agent_channel_url", "revision", "version"], TestJson.Names(members));
        Assert.Equal(JsonValueKind.Number, members["version"].ValueKind);
        Assert.Equal("1", members["version"].GetRawText());
        Assert.Equal(JsonValueKind.Number, members["revision"].ValueKind);
        Assert.Equal("3", members["revision"].GetRawText());
        Assert.Equal(JsonValueKind.String, members["agent_channel_url"].ValueKind);
        Assert.Equal("https://host/dvls", members["agent_channel_url"].GetString());
    }

    // CONTRACT.md §5.2: `agent_channel_url` is absent when the server does not offer the channel,
    // and §1 omits an absent field rather than writing null.
    [Fact]
    public void JsonOmitsAnAbsentAgentChannelUrl()
    {
        IdentityConfig config = IdentityConfig.Create(3);

        Dictionary<string, JsonElement> members = TestJson.Members(config.ToUtf8Json());

        Assert.Equal(["revision", "version"], TestJson.Names(members));
        Assert.Null(config.AgentChannelUrl);
    }

    // CONTRACT.md §5.2: `revision` is an unsigned 64-bit integer, with no starting value the agent assumes.
    // A double holds no more than 53 bits, so it would round the largest revisions.
    [Theory]
    [InlineData(0UL, "0")]
    [InlineData(9007199254740993UL, "9007199254740993")]
    [InlineData(18446744073709551615UL, "18446744073709551615")]
    public void JsonWritesEveryRevisionExactly(ulong revision, string expected)
    {
        IdentityConfig config = IdentityConfig.Create(revision);

        Dictionary<string, JsonElement> members = TestJson.Members(config.ToUtf8Json());

        Assert.Equal(expected, members["revision"].GetRawText());
        Assert.Equal(revision, config.Revision);
    }

    // CONTRACT.md §5.2: `agent_channel_url` is an absolute `https` URL without a query or fragment.
    // RFC 9110 §4.2.4: a sender does not generate user information in an `https` URI.
    [Theory]
    [InlineData("")]
    [InlineData("/dvls")]
    [InlineData("host/dvls")]
    [InlineData("http://host/dvls")]
    [InlineData("wss://host/dvls")]
    [InlineData("https:///dvls")]
    [InlineData("https://host/dvls?tenant=1")]
    [InlineData("https://host/dvls?")]
    [InlineData("https://host/dvls#top")]
    [InlineData("https://host/dvls#")]
    [InlineData("https://admin@host/dvls")]
    [InlineData("https://@host/dvls")]
    public void CreateRejectsAnotherAgentChannelUrl(string agentChannelUrl)
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => IdentityConfig.Create(1, agentChannelUrl));

        Assert.Equal("agentChannelUrl", exception.ParamName);
    }

    // CONTRACT.md §7.2: the agent prepends the URL path to `/devolutions.agent.channel.v1.AgentChannel/Connect`,
    // so a URL ending in a slash would put two slashes in the gRPC path.
    [Theory]
    [InlineData("https://host/dvls", "https://host/dvls")]
    [InlineData("https://host/dvls/", "https://host/dvls")]
    [InlineData("https://host/", "https://host")]
    [InlineData("https://host", "https://host")]
    public void AgentChannelUrlEndsWithoutASlash(string agentChannelUrl, string expected)
    {
        IdentityConfig config = IdentityConfig.Create(1, agentChannelUrl);

        Assert.Equal(expected, TestJson.Members(config.ToUtf8Json())["agent_channel_url"].GetString());
        Assert.Equal(expected, config.AgentChannelUrl);
    }

    // CONTRACT.md §5.2: product-specific config fields, such as a PSU channel URL, may coexist with the others.
    [Fact]
    public void JsonHasTheProductFieldsBesideTheContractMembers()
    {
        const string ChannelUrl = "\"https://psu/channel\"";
        const string Limits = """{"max_sessions": 4, "paths": ["a", "b"], "enabled": true, "ratio": 0.5}""";

        IdentityConfig config = IdentityConfig.Create(
            3,
            "https://host/dvls",
            [new("psu_channel_url", TestJson.Parse(ChannelUrl)), new("policy_limits", TestJson.Parse(Limits))]);

        Dictionary<string, JsonElement> members = TestJson.Members(config.ToUtf8Json());
        Assert.Equal(
            ["agent_channel_url", "policy_limits", "psu_channel_url", "revision", "version"],
            TestJson.Names(members));
        Assert.True(JsonElement.DeepEquals(TestJson.Parse(ChannelUrl), members["psu_channel_url"]));
        Assert.True(JsonElement.DeepEquals(TestJson.Parse(Limits), members["policy_limits"]));
    }

    // CONTRACT.md §1: JSON keys are snake_case, lowercase words of letters and digits joined by single underscores.
    [Theory]
    [InlineData("a")]
    [InlineData("psu_channel_url")]
    [InlineData("ipv4_address")]
    [InlineData("tier_2")]
    public void CreateAcceptsASnakeCaseProductFieldName(string name)
    {
        IdentityConfig config = IdentityConfig.Create(1, null, [new(name, TestJson.Parse("true"))]);

        Assert.Equal(JsonValueKind.True, TestJson.Members(config.ToUtf8Json())[name].ValueKind);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Channel")]
    [InlineData("psuChannel")]
    [InlineData("psu-channel")]
    [InlineData("psu channel")]
    [InlineData("_psu")]
    [InlineData("psu_")]
    [InlineData("psu__channel")]
    [InlineData("2fa")]
    [InlineData("psu\n")]
    [InlineData("caf\u00E9")]
    public void CreateRejectsAProductFieldNameThatIsNotSnakeCase(string name)
    {
        AssertRejectsProductFields([new(name, TestJson.Parse("true"))]);
    }

    // CONTRACT.md §5.2 defines these members, so a product field of one of these names would repeat it.
    [Theory]
    [InlineData("version")]
    [InlineData("revision")]
    [InlineData("agent_channel_url")]
    public void CreateRejectsAProductFieldNamedAfterAContractMember(string name)
    {
        AssertRejectsProductFields([new(name, TestJson.Parse("2"))]);
    }

    // RFC 8259 §4: with a repeated name, receivers disagree on the value, as CONTRACT.md §1 notes of request bodies.
    [Fact]
    public void CreateRejectsARepeatedProductFieldName()
    {
        AssertRejectsProductFields(
            [new("psu_channel_url", TestJson.Parse("\"a\"")), new("psu_channel_url", TestJson.Parse("\"b\""))]);
    }

    // CONTRACT.md §1: an absent field is omitted, never written as null.
    [Fact]
    public void CreateRejectsANullProductFieldValue()
    {
        AssertRejectsProductFields([new("psu_channel_url", TestJson.Parse("null"))]);
    }

    // The default JsonElement holds no JSON value at all.
    [Fact]
    public void CreateRejectsAProductFieldWithoutAValue()
    {
        AssertRejectsProductFields([new("psu_channel_url", default)]);
    }

    [Fact]
    public void CreateRejectsAProductFieldWithoutAName()
    {
        AssertRejectsProductFields([new(null!, TestJson.Parse("true"))]);
    }

    // RFC 8259 §8.1: JSON text exchanged between systems is UTF-8, which cannot encode an unpaired surrogate.
    // Failing here keeps every later serialization of the config from failing.
    [Fact]
    public void CreateRejectsAProductFieldValueThatIsNotUnicodeText()
    {
        AssertRejectsProductFields([new("label", TestJson.Parse("""["ok", "\ud800"]"""))]);
    }

    // A JsonElement reads from its JsonDocument, which the host may dispose once the config exists.
    [Fact]
    public void ConfigOutlivesTheDocumentOfItsProductFields()
    {
        const string Limits = """{"paths": ["a", "b"]}""";
        IdentityConfig config;

        using (JsonDocument document = JsonDocument.Parse(Limits))
        {
            config = IdentityConfig.Create(1, null, [new("policy_limits", document.RootElement)]);
        }

        JsonElement written = TestJson.Members(config.ToUtf8Json())["policy_limits"];
        Assert.True(JsonElement.DeepEquals(TestJson.Parse(Limits), written));
    }

    // A config is immutable, and the response bodies and ConfigUpdate messages write its JSON as it was created.
    [Fact]
    public void ChangingTheReturnedJsonLeavesTheConfigUnchanged()
    {
        IdentityConfig config = IdentityConfig.Create(3, "https://host/dvls");
        byte[] first = config.ToUtf8Json();
        byte[] original = [.. first];

        first.AsSpan().Fill((byte)' ');

        Assert.Equal(original, config.ToUtf8Json());
    }

    private static void AssertRejectsProductFields(KeyValuePair<string, JsonElement>[] productFields)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => IdentityConfig.Create(1, "https://host/dvls", productFields));

        Assert.Equal("productFields", exception.ParamName);
    }
}
