using System;
using System.Reflection;

using WixSharp;

using Xunit;

namespace DevolutionsAgent.Installer.Tests;

public sealed class PolicyConsentDiscoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DiscoveryIsTransactionalAndArchitectureCorrect(bool win64)
    {
        RegValue value = CreateDiscoveryValue("ProtocolVersion", "2.0", win64);

        Assert.Equal(RegistryHive.LocalMachine, value.Root);
        Assert.Equal(@"Software\Devolutions\Agent\PolicyConsentHelper", value.Key);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
        Assert.Equal(win64, value.Win64);
    }

    [Fact]
    public void DiscoveryPublishesTheFixedHelperIdentity()
    {
        RegValue value = CreateDiscoveryValue(
            "ExecutablePath",
            "[INSTALLDIR]DevolutionsAgentPolicyConsent.exe",
            true);

        Assert.Equal("[INSTALLDIR]DevolutionsAgentPolicyConsent.exe", value.Value);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
    }

    private static RegValue CreateDiscoveryValue(string name, string value, bool win64)
    {
        Type program = Assembly.Load("DevolutionsAgent").GetType("DevolutionsAgent.Program", throwOnError: true);
        MethodInfo method = program.GetMethod(
            "CreatePolicyConsentRegistryValue",
            BindingFlags.Static | BindingFlags.NonPublic);
        return Assert.IsType<RegValue>(method.Invoke(null, [name, value, win64]));
    }
}
