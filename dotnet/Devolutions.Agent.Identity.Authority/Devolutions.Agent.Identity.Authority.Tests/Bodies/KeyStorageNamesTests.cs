namespace Devolutions.Agent.Identity.Authority.Tests;

public class KeyStorageNamesTests
{
    // The names of the table, which an authority sends in a key storage policy.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [Fact]
    public void NamesAreThoseOfTheTable()
    {
        string[] expected = ["file", "tpm", "windows_software_provider"];

        Assert.Equal(expected, KeyStorageNames.All.Order(StringComparer.Ordinal));
        Assert.Equal(
            expected,
            new[] { KeyStorageNames.File, KeyStorageNames.Tpm, KeyStorageNames.WindowsSoftwareProvider });
    }

    // The agent reports its key storage under these keys.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    [Fact]
    public void MetadataKeysAreThoseTheAgentSends()
    {
        Assert.Equal("key_storage", AgentMetadataKeys.KeyStorage);
        Assert.Equal("key_storage_available", AgentMetadataKeys.KeyStorageAvailable);
    }

    // `key_storage_available` joins the names with `,`, such as `file,windows_software_provider`.
    [Theory]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    [InlineData("file,windows_software_provider", new[] { "file", "windows_software_provider" })]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    [InlineData("tpm", new[] { "tpm" })]
    // The table can gain names, which a newer agent reports, so a name the library does not know is still reported.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    [InlineData("file,smart_card", new[] { "file", "smart_card" })]
    public void ParseAvailableSplitsTheNames(string value, string[] expected)
    {
        Assert.Equal(expected, KeyStorageNames.ParseAvailable(value));
    }

    // oracle: spec Framework Design Guidelines §Validating Arguments
    [Fact]
    public void ParseAvailableRejectsANullValue()
    {
        Assert.Throws<ArgumentNullException>(() => KeyStorageNames.ParseAvailable(null!));
    }
}
