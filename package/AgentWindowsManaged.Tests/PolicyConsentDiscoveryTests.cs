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
        Assert.Equal(
            win64 ? "Type=string; Component:Win64=yes" : "Type=string",
            value.AttributesDefinition);
    }

    [Theory]
    [InlineData(Platform.x86, false)]
    [InlineData(Platform.x64, true)]
    [InlineData(Platform.arm64, true)]
    public void DiscoveryUsesTheConsumerNativeRegistryView(Platform platform, bool expected)
    {
        Type program = System.Reflection.Assembly
            .Load("DevolutionsAgent")
            .GetType("DevolutionsAgent.Program", throwOnError: true);
        MethodInfo method = program.GetMethod(
            "Use64BitRegistryView",
            BindingFlags.Static | BindingFlags.NonPublic);

        Assert.Equal(expected, Assert.IsType<bool>(method.Invoke(null, [platform])));
    }

    [Fact]
    public void DiscoveryPublishesTheFixedHelperIdentity()
    {
        RegValue executablePath = CreateDiscoveryValue(
            "ExecutablePath",
            "[INSTALLDIR]DevolutionsAgentPolicyConsent.exe",
            true);
        RegValue signer = CreateDiscoveryValue(
            "CurrentUiSignerSpkiSha256",
            "e43ed3368eaabff61abc79eb338cba9da88a80d93b751735ff417f26afa579a8",
            true);
        RegValue brokerPipe = CreateDiscoveryValue(
            "BrokerPipeName",
            @"\\.\pipe\Devolutions.Now.PackageBroker.v1",
            true);

        Assert.Equal("[INSTALLDIR]DevolutionsAgentPolicyConsent.exe", executablePath.Value);
        Assert.Equal(
            "e43ed3368eaabff61abc79eb338cba9da88a80d93b751735ff417f26afa579a8",
            signer.Value);
        Assert.Equal(@"\\.\pipe\Devolutions.Now.PackageBroker.v1", brokerPipe.Value);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, executablePath.RegistryKeyAction);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, signer.RegistryKeyAction);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, brokerPipe.RegistryKeyAction);
    }

    private static RegValue CreateDiscoveryValue(string name, string value, bool win64)
    {
        Type program = System.Reflection.Assembly
            .Load("DevolutionsAgent")
            .GetType("DevolutionsAgent.Program", throwOnError: true);
        MethodInfo method = program.GetMethod(
            "CreatePolicyConsentRegistryValue",
            BindingFlags.Static | BindingFlags.NonPublic);
        return Assert.IsType<RegValue>(method.Invoke(null, [name, value, win64]));
    }
}
