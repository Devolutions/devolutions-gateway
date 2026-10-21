using System.Text.Json;

namespace Devolutions.AgentIdentity.Tests;

public class IdentityConfigTests
{
    // `config` holds `version`, which is 1, `revision` and `agent_channel_url`.
    // An agent reads both numbers as integers, so 1.0 or 3e0 would not do.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
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

    // CONTRACT.agent-identity.md §5.2: `agent_channel_url` is absent when the server does not offer the channel,
    // and §1 omits an absent field rather than writing null.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [Fact]
    public void JsonOmitsAnAbsentAgentChannelUrl()
    {
        IdentityConfig config = IdentityConfig.Create(3);

        Dictionary<string, JsonElement> members = TestJson.Members(config.ToUtf8Json());

        Assert.Equal(["revision", "version"], TestJson.Names(members));
        Assert.Null(config.AgentChannelUrl);
    }

    // `revision` is an unsigned 64-bit integer, with no starting value the agent assumes.
    // A double holds no more than 53 bits, so it would round the largest revisions.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
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

    // CONTRACT.agent-identity.md §5.2: `agent_channel_url` is an absolute `https` URL without a query or fragment.
    // RFC 9110 §4.2.4: a sender does not generate user information in an `https` URI.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("/dvls")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("host/dvls")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("http://host/dvls")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("wss://host/dvls")]
    // oracle: spec RFC 9110 §4.2.2
    [InlineData("https:///dvls")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("https://host/dvls?tenant=1")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    // oracle: spec RFC 3986 §3.4
    [InlineData("https://host/dvls?")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    [InlineData("https://host/dvls#top")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    // oracle: spec RFC 3986 §3.5
    [InlineData("https://host/dvls#")]
    // oracle: spec RFC 9110 §4.2.4
    [InlineData("https://admin@host/dvls")]
    // oracle: spec RFC 9110 §4.2.4
    [InlineData("https://@host/dvls")]
    public void CreateRejectsAnotherAgentChannelUrl(string agentChannelUrl)
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => IdentityConfig.Create(1, agentChannelUrl));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("agentChannelUrl", exception.ParamName);
    }

    // The agent prepends the URL path to `/devolutions.agent.channel.v1.AgentChannel/Connect`,
    // so a URL ending in a slash would put two slashes in the gRPC path.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §7.2
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

    // Product-specific config fields, such as a PSU channel URL, may coexist with the others.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
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

    // JSON keys are snake_case, lowercase words of letters and digits joined by single underscores.
    // zz09 starts and goes on with the last letter, and holds the first and last digits.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [Theory]
    [InlineData("a")]
    [InlineData("psu_channel_url")]
    [InlineData("ipv4_address")]
    [InlineData("tier_2")]
    [InlineData("zz09")]
    public void CreateAcceptsASnakeCaseProductFieldName(string name)
    {
        IdentityConfig config = IdentityConfig.Create(1, null, [new(name, TestJson.Parse("true"))]);

        Assert.Equal(JsonValueKind.True, TestJson.Members(config.ToUtf8Json())[name].ValueKind);
    }

    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("Channel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("psuChannel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("psu-channel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("psu channel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("psu\n")]
    public void CreateRejectsAProductFieldNameThatIsNotSnakeCase(string name)
    {
        AssertRejectsProductFields([new(name, TestJson.Parse("true"))]);
    }

    // CONTRACT.agent-identity.md §5.2 defines these members, so a product field of one of these names would repeat it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    // oracle: spec RFC 8259 §4
    [Theory]
    [InlineData("version")]
    [InlineData("revision")]
    [InlineData("agent_channel_url")]
    public void CreateRejectsAProductFieldNamedAfterAContractMember(string name)
    {
        AssertRejectsProductFields([new(name, TestJson.Parse("2"))]);
    }

    // An object member is a name and a value.
    // The default JsonElement holds no JSON value at all.
    // oracle: spec RFC 8259 §4
    [Fact]
    public void CreateRejectsAProductFieldWithoutAValue()
    {
        AssertRejectsProductFields([new("psu_channel_url", default)]);
    }

    // A member name is a string, which a null name is not.
    // oracle: spec RFC 8259 §4
    [Fact]
    public void CreateRejectsAProductFieldWithoutAName()
    {
        AssertRejectsProductFields([new(null!, TestJson.Parse("true"))]);
    }

    // RFC 8259 §8.1: JSON text exchanged between systems is UTF-8, which cannot encode an unpaired surrogate.
    // Failing here keeps every later serialization of the config from failing.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [InlineData("""{"\ud800": 1}""")]
    public void CreateRejectsAProductFieldValueThatIsNotUnicodeText(string value)
    {
        AssertRejectsProductFields([new("label", TestJson.Parse(value))]);
    }

    // JSON keys are snake_case, so the members inside a product field's value are too,
    // whether an object or an array holds them.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [Theory]
    [InlineData("""{"maxSessions": 4}""")]
    [InlineData("""{"limits": {"max_sessions": 4, "Max_paths": 2}}""")]
    [InlineData("""[{"Path": "a"}]""")]
    [InlineData("""{"paths": [["a"], [{"pathName": "b"}]]}""")]
    public void CreateRejectsAMemberNameThatIsNotSnakeCaseInAValue(string value)
    {
        AssertRejectsProductFields([new("policy_limits", TestJson.Parse(value))]);
    }

    // RFC 8259 §4: with a repeated name, receivers disagree on the value,
    // as CONTRACT.agent-identity.md §1 notes of request bodies.
    // A product field is a member of the config, and a name and its escaped spelling are the same name.
    private static readonly Dictionary<string, KeyValuePair<string, JsonElement>[]> RepeatedMemberNames = new()
    {
        ["product field"] =
            [new("psu_channel_url", TestJson.Parse("\"a\"")), new("psu_channel_url", TestJson.Parse("\"b\""))],
        ["member of a value"] =
            [new("policy_limits", TestJson.Parse("""{"max_sessions": 4, "max_sessions": 5}"""))],
        ["member of an object in an array"] =
            [new("policy_limits", TestJson.Parse("""{"limits": [{"max_sessions": 4, "max_sessions": 5}]}"""))],
        // oracle: spec RFC 8259 §7
        ["member of a value with an escaped name"] =
            [new("policy_limits", TestJson.Parse("""{"max_sessions": 4, "max\u005Fsessions": 5}"""))],
    };

    public static TheoryData<string> RepeatedMemberNameForms => new(RepeatedMemberNames.Keys);

    // oracle: spec RFC 8259 §4
    [Theory]
    [MemberData(nameof(RepeatedMemberNameForms))]
    public void CreateRejectsARepeatedMemberName(string form)
    {
        AssertRejectsProductFields(RepeatedMemberNames[form]);
    }

    // An absent field is omitted, never written as null, at any depth.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    [Theory]
    [InlineData("psu_channel_url", "null")]
    [InlineData("policy_limits", """{"proxy": null}""")]
    [InlineData("policy_limits", """[{"proxy": null}]""")]
    public void CreateRejectsANullFieldOrMember(string name, string value)
    {
        AssertRejectsProductFields([new(name, TestJson.Parse(value))]);
    }

    // RFC 8259 §4 asks for unique names within an object, and §5 makes array elements values rather than members.
    // A name repeats only within one object, and an array element is no field, so it may be null.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §5.2
    // oracle: spec RFC 8259 §4
    // oracle: spec RFC 8259 §5
    [Fact]
    public void CreateAcceptsAValueWhoseMembersFollowTheConventions()
    {
        const string Limits = """{"a": {"b": 1}, "c": {"b": [1, {"b": 2}]}, "d": [{"b": 1}, {"b": 1}, null]}""";

        IdentityConfig config = IdentityConfig.Create(1, null, [new("policy_limits", TestJson.Parse(Limits))]);

        JsonElement written = TestJson.Members(config.ToUtf8Json())["policy_limits"];
        Assert.True(JsonElement.DeepEquals(TestJson.Parse(Limits), written));
    }

    // A JsonElement reads from its JsonDocument, which the host may dispose once the config exists,
    // so the config keeps a copy of each product field rather than the argument it validated.
    // oracle: spec Framework Design Guidelines §Validating Arguments
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

    private static void AssertRejectsProductFields(KeyValuePair<string, JsonElement>[] productFields)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => IdentityConfig.Create(1, "https://host/dvls", productFields));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productFields", exception.ParamName);
    }
}
