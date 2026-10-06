using System.Linq;

using DevolutionsAgent.Helpers;
using DevolutionsAgent.Resources;

using Xunit;

namespace DevolutionsAgent.Installer.Tests;

public sealed class PackageBrokerFeatureTests
{
    [Fact]
    public void FeatureIsAnOptionalAgentChildDisabledByDefault()
    {
        Assert.Equal("F.PackageBroker", Features.PACKAGE_BROKER_FEATURE.Id);
        Assert.Contains(Features.PACKAGE_BROKER_FEATURE, Features.AGENT_FEATURE.Children);
        Assert.False(Features.PACKAGE_BROKER_FEATURE.IsEnabled);
        Assert.True(Features.PACKAGE_BROKER_FEATURE.AllowChange);
        Assert.DoesNotContain(Features.PACKAGE_BROKER_FEATURE, Features.ExperimentalFeatures);
    }

    [Fact]
    public void FeatureTogglesThePackageBrokerSectionOfAgentJson()
    {
        // ConfigureFeatures derives the agent.json section from the feature id, and the agent reads
        // it as ConfFile::package_broker, serialized in PascalCase.
        Assert.Equal("PackageBroker", PackageBrokerUpgrade.ConfigSection);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("not json", false)]
    [InlineData("[]", false)]
    [InlineData("{}", false)]
    [InlineData("{\"PackageBroker\":true}", false)]
    [InlineData("{\"PackageBroker\":{}}", false)]
    [InlineData("{\"PackageBroker\":{\"Enabled\":false}}", false)]
    [InlineData("{\"PackageBroker\":{\"Enabled\":\"true\"}}", false)]
    [InlineData("{\"packageBroker\":{\"Enabled\":true}}", false)]
    [InlineData("{\"PackageBroker\":{\"Enabled\":true}}", true)]
    [InlineData("{\"PackageBroker\":{\"Enabled\":true,\"PipeName\":\"custom\",\"PolicyPath\":\"C:\\\\policy.json\"}}", true)]
    public void ReadsEnabledStateFromAgentJson(string agentConfig, bool expected)
    {
        Assert.Equal(expected, PackageBrokerUpgrade.IsEnabledInConfig(agentConfig));
    }

    private const string EnabledConfig = "{\"PackageBroker\":{\"Enabled\":true}}";

    private const string DisabledConfig = "{\"PackageBroker\":{\"Enabled\":false}}";

    [Fact]
    public void FirstInstallDoesNotSelectFeature()
    {
        Assert.False(PackageBrokerUpgrade.ShouldSelect([], EnabledConfig));
    }

    [Fact]
    public void UpgradeFromReleaseWithoutFeatureFollowsAgentJson()
    {
        string[] previous = ["F.Agent", "F.Updater", "F.Tunnel", "F.PsuAgent", "F.Pedm", "F.Session"];

        Assert.True(PackageBrokerUpgrade.ShouldSelect([previous], EnabledConfig));
        Assert.False(PackageBrokerUpgrade.ShouldSelect([previous], DisabledConfig));
        Assert.False(PackageBrokerUpgrade.ShouldSelect([previous], null));
    }

    [Fact]
    public void UpgradeFromReleaseWithFeatureKeepsRecordedState()
    {
        // Once the previous product defines the feature, its recorded state wins, so a deselected
        // feature stays deselected even if agent.json was edited by hand afterwards.
        string[] previous = ["F.Agent", "F.Updater", "F.PackageBroker"];

        Assert.False(PackageBrokerUpgrade.ShouldSelect([previous], EnabledConfig));
        Assert.False(PackageBrokerUpgrade.ShouldSelect([["F.Agent"], previous], EnabledConfig));
    }

    [Fact]
    public void FeatureHasLocalizedNameAndDescription()
    {
        string[] keys = [Strings.FeaturePackageBrokerName, Strings.FeaturePackageBrokerDescription];

        Assert.Equal("!(loc.FeaturePackageBrokerName)", Features.PACKAGE_BROKER_FEATURE.Name);
        Assert.Equal("!(loc.FeaturePackageBrokerDescription)", Features.PACKAGE_BROKER_FEATURE.Description);

        foreach (string culture in new[] { "en-us", "fr-fr", "sv-se" })
        {
            using System.IO.Stream stream = typeof(Features).Assembly
                .GetManifestResourceStream($"DevolutionsAgent.Resources.DevolutionsAgent_{culture}.wxl");
            Assert.NotNull(stream);

            System.Xml.Linq.XDocument wxl = System.Xml.Linq.XDocument.Load(stream);
            string[] ids = wxl.Descendants().Where(e => e.Name.LocalName == "String").Select(e => (string)e.Attribute("Id")).ToArray();

            foreach (string key in keys)
            {
                Assert.Contains(key, ids);
            }
        }
    }
}
