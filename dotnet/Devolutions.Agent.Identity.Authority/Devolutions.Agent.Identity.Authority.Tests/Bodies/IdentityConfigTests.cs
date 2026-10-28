using System.Text.Json;

using Google.Protobuf;

namespace Devolutions.Agent.Identity.Authority.Tests;

public class IdentityConfigTests
{
    // `config` holds `version`, which is 1, `revision` and `agent_channel_url`.
    // An agent reads both numbers as integers, so 1.0 or 3e0 would not do.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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

    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Theory]
    [MemberData(nameof(UnacceptableUrls.Rows), MemberType = typeof(UnacceptableUrls))]
    public void CreateRejectsAnotherAgentChannelUrl(string agentChannelUrl)
    {
        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => IdentityConfig.Create(1, agentChannelUrl));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("agentChannelUrl", exception.ParamName);
    }

    // `agent_channel_url` is an absolute `https` URL without an `@`, a query or a fragment,
    // which the config carries as the host gave it.
    // Whether a URL ending in a slash is rejected or written without the slash is the library's choice.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    [Theory]
    [InlineData("https://host/dvls")]
    [InlineData("https://host")]
    public void AgentChannelUrlIsWrittenAsGiven(string agentChannelUrl)
    {
        IdentityConfig config = IdentityConfig.Create(1, agentChannelUrl);

        Assert.Equal(agentChannelUrl, TestJson.Members(config.ToUtf8Json())["agent_channel_url"].GetString());
        Assert.Equal(agentChannelUrl, config.AgentChannelUrl);
    }

    // `agent_channel_url` has no trailing slash, and the agent removes trailing slashes from one that has them.
    // Create may reject a URL ending in slashes, but a config it creates holds the URL without them.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-url
    [Theory]
    [InlineData("https://host/dvls/", "https://host/dvls")]
    [InlineData("https://host/dvls//", "https://host/dvls")]
    [InlineData("https://host/", "https://host")]
    public void CreateRejectsOrRemovesTheTrailingSlashesOfAnAgentChannelUrl(
        string agentChannelUrl,
        string withoutSlashes)
    {
        Creation creation = CreateFrom(agentChannelUrl);

        Assert.Contains(creation, (Creation[])[Creation.Holding(withoutSlashes), Creation.Rejection]);
    }

    // `config.key_storage` is the identity's key storage policy, an object with `backends` and `required`.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [Fact]
    public void JsonHasTheKeyStoragePolicy()
    {
        KeyStoragePolicy policy = KeyStoragePolicy.Create(["tpm", "windows_software_provider"], required: true);

        IdentityConfig config = IdentityConfig.Create(3, "https://host/dvls", keyStorage: policy);

        Dictionary<string, JsonElement> members = TestJson.Members(config.ToUtf8Json());
        Assert.Equal(["agent_channel_url", "key_storage", "revision", "version"], TestJson.Names(members));
        Assert.True(JsonElement.DeepEquals(
            TestJson.Parse("""{ "backends": ["tpm", "windows_software_provider"], "required": true }"""),
            members["key_storage"]));
        Assert.Same(policy, config.KeyStorage);
    }

    // Product-specific config fields, such as a PSU channel URL, may coexist with the others.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("Channel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("psuChannel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("psu-channel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("psu channel")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("psu\n")]
    public void CreateRejectsAProductFieldNameThatIsNotSnakeCase(string name)
    {
        AssertRejectsProductFields([new(name, TestJson.Parse("true"))]);
    }

    // CONTRACT.agent-identity.md §5.2 defines these members, so a product field of one of these names would repeat it.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: spec RFC 8259 §4
    [Theory]
    [InlineData("version")]
    [InlineData("revision")]
    [InlineData("agent_channel_url")]
    [InlineData("key_storage")]
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [InlineData("""{"\ud800": 1}""")]
    public void CreateRejectsAProductFieldValueThatIsNotUnicodeText(string value)
    {
        AssertRejectsProductFields([new("label", TestJson.Parse(value))]);
    }

    // JSON keys are snake_case, so the members inside a product field's value are too,
    // whether an object or an array holds them.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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

    // A `ServerMessage` whose `id` is a lowercase hyphenated UUID and whose `ConfigUpdate` carries J bytes of JSON
    // takes J + 46 bytes, for J from 16,384 to 2,097,147, where both lengths below are 3-byte varints:
    //   1 byte    tag of `id`: field 1, wire type LEN, (1 << 3) | 2 = 10
    //   1 byte    length of `id`: 36, the characters of a hyphenated UUID
    //   36 bytes  `id`
    //   1 byte    tag of `config_update`: field 15, wire type LEN, (15 << 3) | 2 = 122
    //   3 bytes   length of `ConfigUpdate`: J + 4
    //   1 byte    tag of `config_json`: field 1, wire type LEN, 10
    //   3 bytes   length of `config_json`: J
    //   J bytes   `config_json`
    // `correlation_id` is unset, so it takes no bytes.
    // An envelope of 65,536 bytes therefore carries 65,490 bytes of JSON.
    private const int LargestConfigJsonBytes = 65_490;

    // Each side of the agent channel accepts envelopes up to 65,536 bytes.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    [Fact]
    public void CreateAcceptsAConfigWhoseConfigUpdateIsExactly64KiB()
    {
        IdentityConfig config = IdentityConfig.Create(1, null, PaddedProductFields(LargestConfigJsonBytes));

        // oracle: spec Protocol Buffers Encoding §Length-Delimited Records
        Assert.Equal(65_536, ChannelMessages.ConfigUpdate(config).ToByteArray().Length);
    }

    // Each side of the agent channel sends no envelope larger than 65,536 bytes,
    // so an authority never holds a config whose `ConfigUpdate` would exceed that.
    // One byte more JSON than the largest config makes a 65,537-byte envelope.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    // oracle: spec Protocol Buffers Encoding §Length-Delimited Records
    [Fact]
    public void CreateRejectsAConfigWhoseConfigUpdateWouldExceed64KiB()
    {
        KeyValuePair<string, JsonElement>[] productFields = PaddedProductFields(LargestConfigJsonBytes + 1);

        ArgumentException exception =
            Assert.Throws<ArgumentException>(() => IdentityConfig.Create(1, null, productFields));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productFields", exception.ParamName);
    }

    // Returns one product field, padded with ASCII letters, that makes the JSON of a config with revision 1 and no
    // agent channel URL `jsonBytes` long.
    // Each letter adds one byte, since UTF-8 encodes an ASCII letter, which JSON need not escape, in one byte.
    private static KeyValuePair<string, JsonElement>[] PaddedProductFields(int jsonBytes)
    {
        int unpaddedBytes = IdentityConfig.Create(1, null, Padding(0)).ToUtf8Json().Length;

        return Padding(jsonBytes - unpaddedBytes);

        static KeyValuePair<string, JsonElement>[] Padding(int letters)
        {
            return [new("padding", TestJson.Parse($"\"{new string('a', letters)}\""))];
        }
    }

    private static void AssertRejectsProductFields(KeyValuePair<string, JsonElement>[] productFields)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => IdentityConfig.Create(1, "https://host/dvls", productFields));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("productFields", exception.ParamName);
    }

    // What Create makes of the URL: the `agent_channel_url` that the JSON of its config holds, or a rejection.
    private static Creation CreateFrom(string agentChannelUrl)
    {
        IdentityConfig config;

        try
        {
            config = IdentityConfig.Create(1, agentChannelUrl);
        }
        catch (ArgumentException)
        {
            return Creation.Rejection;
        }

        return Creation.Holding(TestJson.Members(config.ToUtf8Json())["agent_channel_url"].GetString());
    }

    // What Create makes of an agent channel URL: a rejection, or a config whose JSON holds `AgentChannelUrl`.
    private sealed record Creation(bool Rejected, string? AgentChannelUrl)
    {
        public static Creation Rejection { get; } = new(Rejected: true, AgentChannelUrl: null);

        public static Creation Holding(string? agentChannelUrl)
        {
            return new Creation(Rejected: false, AgentChannelUrl: agentChannelUrl);
        }
    }
}
