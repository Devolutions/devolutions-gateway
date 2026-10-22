using System.IO;

using DevolutionsAgent.Actions;

using Xunit;

namespace DevolutionsAgent.Installer.Tests;

public sealed class PsuConfigUpgradeTests
{
    [Theory]
    [InlineData("{\"PsuAgent\":{\"ServerUrl\":\"https://psu.example\",\"AppToken\":\"token\"}}", true)]
    [InlineData("{\"PsuAgent\":{\"ServerUrl\":\"https://psu.example\",\"DeviceEnrollment\":{\"RootThumbprint\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}}", true)]
    [InlineData("{\"PsuAgent\":{\"ServerUrl\":\"https://psu.example\",\"DeviceEnrollment\":{}}}", false)]
    [InlineData("{\"PsuAgent\":{\"AppToken\":\"token\"}}", false)]
    public void CompletenessRecognizesLegacyAndDeviceAuthentication(string agentConfig, bool expected)
    {
        string configPath = Path.GetTempFileName();
        try
        {
            File.WriteAllText(configPath, agentConfig);

            Assert.Equal(expected, CustomActions.PsuConfigIsComplete(configPath));
        }
        finally
        {
            File.Delete(configPath);
        }
    }
}
