using System.Runtime.CompilerServices;
using System.Text.Json;

using NJsonSchema;

using Xunit;

namespace Devolutions.UniGetUI.Broker.Policy.Tests;

public class PolicyTests
{
    private static string PolicyCrateRoot { get; } = ResolvePolicyCrateRoot();

    private static string SamplesDir => Path.Combine(PolicyCrateRoot, "assets", "samples");

    private static string PolicySchema => Path.Combine(PolicyCrateRoot, "schema", "unigetui.package-policy.schema.json");

    public static IEnumerable<object[]> PolicySamples() =>
        Directory.GetFiles(SamplesDir, "*.policy.*").Select(f => new object[] { f });

    [Theory]
    [MemberData(nameof(PolicySamples))]
    public async Task Policy_samples_parse_and_validate_against_rust_schema(string path)
    {
        var policy = ParsePolicy(path);
        var schema = await JsonSchema.FromFileAsync(PolicySchema);
        var errors = schema.Validate(policy.ToJson());

        Assert.True(
            errors.Count == 0,
            $"{Path.GetFileName(path)} failed policy schema validation:\n" +
            string.Join("\n", errors.Select(e => $"  {e.Kind} at {e.Path}")));
    }

    [Fact]
    public async Task Created_policy_validates_against_rust_schema()
    {
        var policy = PolicyDocument.Create("contoso.policy", "Contoso IT");
        policy.Rules.Add(new PolicyRule
        {
            Id = "allow.vscode",
            Priority = 100,
            Decision = Decision.Allow,
            Match = new PolicyMatch
            {
                Operations = [Operation.Install],
                Managers = [ManagerName.Winget],
                PackageIdentifiers = ["Microsoft.VisualStudioCode"],
            },
        });

        var schema = await JsonSchema.FromFileAsync(PolicySchema);
        var errors = schema.Validate(policy.ToJson());

        Assert.True(errors.Count == 0, string.Join("\n", errors.Select(e => $"  {e.Kind} at {e.Path}")));
    }

    [Fact]
    public void Invalid_policy_fixture_is_rejected_by_parser()
    {
        var path = Path.Combine(SamplesDir, "invalid", "policies", "invalid-failure-decision.policy.json");
        var content = File.ReadAllText(path);

        Assert.ThrowsAny<Exception>(() => PolicyDocument.ParseJson(content));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_yaml_is_rejected_with_json_exception(string yaml)
    {
        Assert.Throws<JsonException>(() => PolicyDocument.ParseYaml(yaml));
    }

    [Fact]
    public void Yaml_with_non_scalar_mapping_key_is_rejected_with_json_exception()
    {
        const string yaml = """
        ? [PolicyVersion]
        : 1.0.0
        """;

        Assert.Throws<JsonException>(() => PolicyDocument.ParseYaml(yaml));
    }

    [Fact]
    public void Negative_revision_is_rejected_by_parser()
    {
        var json = MinimalPolicyJson("""
                "Revision": -1,
        """, """
                "Rules": []
        """);

        Assert.Throws<JsonException>(() => PolicyDocument.ParseJson(json));
    }

    [Fact]
    public void Negative_priority_is_rejected_by_parser()
    {
        var json = MinimalPolicyJson("""
                "Revision": 1,
        """, """
                "Rules": [
                    {
                        "Id": "deny.test",
                        "Enabled": true,
                        "Priority": -1,
                        "Decision": "Deny",
                        "Match": {
                            "Operations": ["Install"]
                        }
                    }
                ]
        """);

        Assert.Throws<JsonException>(() => PolicyDocument.ParseJson(json));
    }

    private static PolicyDocument ParsePolicy(string path)
    {
        var content = File.ReadAllText(path);
        var extension = Path.GetExtension(path);
        return extension.Equals(".yaml", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".yml", StringComparison.OrdinalIgnoreCase)
            ? PolicyDocument.ParseYaml(content)
            : PolicyDocument.ParseJson(content);
    }

    private static string ResolvePolicyCrateRoot([CallerFilePath] string thisFile = "")
    {
        var testsDir = Path.GetDirectoryName(thisFile)!;
        return Path.GetFullPath(Path.Combine(testsDir, "..", "..", "crates", "uniget-broker-policy"));
    }

    private static string MinimalPolicyJson(string revision, string rules)
    {
        return $$"""
        {
            "$schema": "https://aka.ms/unigetui/package-policy.schema.1.0.json",
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": {
                "Id": "test.policy",
                "Publisher": "Test",
        {{revision}}
                "PublishedAt": "2026-01-01T00:00:00Z"
            },
            "Enforcement": {
                "DefaultDecision": "Deny",
                "RulePrecedence": "PriorityThenDeny"
            },
        {{rules}}
        }
        """;
    }
}
