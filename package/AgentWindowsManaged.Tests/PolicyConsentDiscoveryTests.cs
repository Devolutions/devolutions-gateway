using System;
using System.Linq;
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

    [Theory]
    [InlineData(Platform.x86, 7)]
    [InlineData(Platform.x64, 14)]
    [InlineData(Platform.arm64, 14)]
    public void AgentMsiPublishesDiscoveryInRequiredRegistryViews(
        Platform platform,
        int expectedCount)
    {
        Type program = System.Reflection.Assembly
            .Load("DevolutionsAgent")
            .GetType("DevolutionsAgent.Program", throwOnError: true);
        MethodInfo method = program.GetMethod(
            "CreatePolicyConsentRegistryValues",
            BindingFlags.Static | BindingFlags.NonPublic,
            binder: null,
            types: [typeof(Platform?), typeof(Version)],
            modifiers: null);

        RegValue[] values = Assert.IsAssignableFrom<System.Collections.Generic.IEnumerable<RegValue>>(
                method.Invoke(null, [platform, new Version(2026, 3, 0)]))
            .ToArray();

        Assert.Equal(expectedCount, values.Length);
        Assert.All(values, value =>
        {
            Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
        });
        Assert.Equal(
            new[]
            {
                "ProtocolVersion",
                "ExecutableName",
                "ExecutablePath",
                "ProductName",
                "ProductVersion",
                "BrokerPipeName",
                "CurrentUiSignerSpkiSha256",
            },
            values.Take(7).Select(value => value.Name));
        Assert.Equal(
            new[]
            {
                "2.0",
                "DevolutionsAgentPolicyConsent.exe",
                "[INSTALLDIR]DevolutionsAgentPolicyConsent.exe",
                "Devolutions Agent Policy Consent",
                "2026.3.0",
                @"\\.\pipe\Devolutions.Now.PackageBroker.v1",
                "e43ed3368eaabff61abc79eb338cba9da88a80d93b751735ff417f26afa579a8",
            },
            values.Take(7).Select(value => value.Value));
        Assert.All(values.Take(7), value =>
        {
            Assert.Equal(platform != Platform.x86, value.Win64);
            Assert.Equal(
                platform == Platform.x86 ? "Type=string" : "Type=string; Component:Win64=yes",
                value.AttributesDefinition);
        });

        if (platform == Platform.x86)
        {
            return;
        }

        Assert.Equal(values.Take(7).Select(value => value.Name), values.Skip(7).Select(value => value.Name));
        Assert.Equal(values.Take(7).Select(value => value.Value), values.Skip(7).Select(value => value.Value));
        Assert.All(values.Skip(7), value =>
        {
            Assert.False(value.Win64);
            Assert.Equal("Type=string", value.AttributesDefinition);
        });
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
