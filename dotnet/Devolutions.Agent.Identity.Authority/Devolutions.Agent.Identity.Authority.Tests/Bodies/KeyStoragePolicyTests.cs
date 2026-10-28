using System.Text;
using System.Text.Json;

namespace Devolutions.Agent.Identity.Authority.Tests;

public class KeyStoragePolicyTests
{
    // The key storage names of the table in CONTRACT.agent-identity.md §5.7.
    private static readonly string[] TableNames = ["file", "windows_software_provider", "tpm"];

    // The policy is an object of `backends`, the names in the authority's order of preference, and `required`,
    // a boolean, as in the contract's example.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [Theory]
    [InlineData(
        new[] { "tpm", "windows_software_provider" },
        true,
        """{ "backends": ["tpm", "windows_software_provider"], "required": true }""")]
    [InlineData(
        new[] { "windows_software_provider", "tpm" },
        true,
        """{ "backends": ["windows_software_provider", "tpm"], "required": true }""")]
    [InlineData(new[] { "file" }, false, """{ "backends": ["file"], "required": false }""")]
    public void JsonHasTheBackendsInOrderAndRequired(string[] backends, bool required, string expected)
    {
        KeyStoragePolicy policy = KeyStoragePolicy.Create(backends, required);

        Assert.True(JsonElement.DeepEquals(TestJson.Parse(expected), TestJson.Parse(Utf8(policy.ToUtf8Json()))));
        Assert.Equal(backends, policy.Backends);
        Assert.Equal(required, policy.Required);
    }

    // `backends` holds 1 to 8 distinct names, and an authority sends only names from the table.
    // With three names in the table, nine names repeat one.
    private static readonly Dictionary<string, string?[]> UnacceptableBackends = new()
    {
        ["no name"] = [],
        ["a repeated name"] = ["tpm", "file", "tpm"],
        ["nine names"] = ["file", "windows_software_provider", "tpm", "file", "windows_software_provider", "tpm", "file",
            "windows_software_provider", "tpm"],
        ["a name outside the table"] = ["file", "smart_card"],
        ["a table name in another case"] = ["TPM"],
        ["a table name with white space"] = ["tpm "],
        ["an empty name"] = [""],
        // oracle: spec Framework Design Guidelines §Validating Arguments
        ["a null name"] = ["file", null],
    };

    public static TheoryData<string> UnacceptableBackendsForms => new(UnacceptableBackends.Keys);

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [Theory]
    [MemberData(nameof(UnacceptableBackendsForms))]
    public void CreateRejectsBackendsOutsideTheRules(string form)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => KeyStoragePolicy.Create(UnacceptableBackends[form]!, required: true));

        // oracle: spec Framework Design Guidelines §Using Standard Exception Types
        Assert.Equal("backends", exception.ParamName);
    }

    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void CreateRejectsNullBackends()
    {
        Assert.Throws<ArgumentNullException>(() => KeyStoragePolicy.Create(null!, required: true));
    }

    // The contract's example, its members in another order (RFC 8259 §4: an object is an unordered collection),
    // and a name spelled with an escape (RFC 8259 §7) are the same policy.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [Theory]
    [InlineData(
        """{ "backends": ["tpm", "windows_software_provider"], "required": true }""",
        new[] { "tpm", "windows_software_provider" },
        true)]
    // oracle: spec RFC 8259 §4
    [InlineData("""{"required":false,"backends":["file"]}""", new[] { "file" }, false)]
    // oracle: spec RFC 8259 §7
    [InlineData("""{"backends":["\u0074pm"],"required":true}""", new[] { "tpm" }, true)]
    public void TryParseReadsAPolicy(string json, string[] backends, bool required)
    {
        Assert.True(KeyStoragePolicy.TryParse(Encoding.UTF8.GetBytes(json), out KeyStoragePolicy? policy));

        Assert.Equal(backends, policy.Backends);
        Assert.Equal(required, policy.Required);
    }

    // `backends` and `required` are both required, `backends` is an array of 1 to 8 distinct names from the table,
    // and `required` is a boolean.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [Theory]
    [InlineData("[]")]
    [InlineData("true")]
    [InlineData("""{"required":true}""")]
    [InlineData("""{"backends":["tpm"]}""")]
    [InlineData("""{"backends":null,"required":true}""")]
    [InlineData("""{"backends":["tpm"],"required":null}""")]
    [InlineData("""{"backends":"tpm","required":true}""")]
    [InlineData("""{"backends":["tpm"],"required":"true"}""")]
    [InlineData("""{"backends":["tpm"],"required":1}""")]
    [InlineData("""{"backends":[],"required":true}""")]
    [InlineData("""{"backends":["tpm","tpm"],"required":true}""")]
    [InlineData("""{"backends":["file","windows_software_provider","tpm","file","windows_software_provider","tpm","file","windows_software_provider","tpm"],"required":true}""")]
    [InlineData("""{"backends":["smart_card"],"required":true}""")]
    [InlineData("""{"backends":["TPM"],"required":true}""")]
    [InlineData("""{"backends":[1],"required":true}""")]
    [InlineData("""{"backends":[null],"required":true}""")]
    [InlineData("""{"backends":[["tpm"]],"required":true}""")]
    // oracle: mutant a TryParse that ignores a member other than backends and required
    [InlineData("""{"backends":["tpm"],"required":true,"extra":1}""")]
    public void TryParseRejectsAPolicyOutsideTheRules(string json)
    {
        Assert.False(KeyStoragePolicy.TryParse(Encoding.UTF8.GetBytes(json), out KeyStoragePolicy? policy));
        Assert.Null(policy);
    }

    // A repeated member name lets two parsers read two policies, whatever the escapes that spell it,
    // and bytes that are not one JSON text have no policy to read.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [InlineData("""{"backends":["tpm"],"required":true,"required":false}""")]
    // oracle: spec RFC 8259 §7
    [InlineData("""{"backends":["tpm"],"required":true,"requir\u0065d":true}""")]
    [InlineData("""{"backends":["tpm"],"backends":["file"],"required":true}""")]
    // oracle: spec RFC 8259 §2
    [InlineData("")]
    // oracle: spec RFC 8259 §2
    [InlineData("""{"backends":["tpm"],"required":true} {}""")]
    // oracle: spec RFC 8259 §2
    [InlineData("""{"backends":["tpm"],"required":true,}""")]
    public void TryParseRejectsJsonThatParsersCanReadDifferently(string json)
    {
        Assert.False(KeyStoragePolicy.TryParse(Encoding.UTF8.GetBytes(json), out _));
    }

    // A policy is written into a config once, so a host that reuses its list of names afterwards
    // changes neither the policy nor the config that carries it.
    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void PolicyKeepsItsNamesWhenTheCallerChangesItsList()
    {
        List<string> names = ["tpm", "windows_software_provider"];
        KeyStoragePolicy policy = KeyStoragePolicy.Create(names, required: true);
        IdentityConfig config = IdentityConfig.Create(1, keyStorage: policy);

        names[0] = "file";
        names.Add("tpm");

        Assert.Equal(["tpm", "windows_software_provider"], policy.Backends);
        Assert.True(JsonElement.DeepEquals(
            TestJson.Parse("""{ "backends": ["tpm", "windows_software_provider"], "required": true }"""),
            TestJson.Members(config.ToUtf8Json())["key_storage"]));
    }

    // Every order of every non-empty set of table names, each required or not.
    public static TheoryData<string, bool> EveryPolicy()
    {
        TheoryData<string, bool> rows = [];

        foreach (string backends in Orderings([], TableNames))
        {
            rows.Add(backends, true);
            rows.Add(backends, false);
        }

        return rows;

        static IEnumerable<string> Orderings(IReadOnlyList<string> prefix, IReadOnlyList<string> rest)
        {
            foreach (string name in rest)
            {
                string[] ordering = [.. prefix, name];

                yield return string.Join(",", ordering);

                foreach (string longer in Orderings(ordering, [.. rest.Where(other => other != name)]))
                {
                    yield return longer;
                }
            }
        }
    }

    // The host stores a policy as its JSON and reloads it, so reading the JSON back gives the same policy.
    // oracle: property round-trip
    [Theory]
    [MemberData(nameof(EveryPolicy))]
    public void TryParseReadsBackWhatToUtf8JsonWrites(string backends, bool required)
    {
        string[] names = backends.Split(',');

        byte[] json = KeyStoragePolicy.Create(names, required).ToUtf8Json();

        Assert.True(KeyStoragePolicy.TryParse(json, out KeyStoragePolicy? policy));
        Assert.Equal(names, policy.Backends);
        Assert.Equal(required, policy.Required);
    }

    private static string Utf8(byte[] bytes)
    {
        return Encoding.UTF8.GetString(bytes);
    }
}
