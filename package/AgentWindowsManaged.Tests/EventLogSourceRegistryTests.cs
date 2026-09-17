using System;
using System.Reflection;

using WixSharp;

using Xunit;

namespace DevolutionsAgent.Installer.Tests;

public sealed class EventLogSourceRegistryTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SourceUsesNativeMsiRegistryLifecycle(bool win64)
    {
        Type program = System.Reflection.Assembly.Load("DevolutionsAgent").GetType("DevolutionsAgent.Program", throwOnError: true);
        MethodInfo method = program.GetMethod(
            "CreateEventLogSourceRegistryValue",
            BindingFlags.Static | BindingFlags.NonPublic);
        RegValue value = Assert.IsType<RegValue>(method.Invoke(null, [win64]));

        Assert.Equal(RegistryHive.LocalMachine, value.Root);
        Assert.Equal(@"SYSTEM\CurrentControlSet\Services\EventLog\Application\Devolutions Agent", value.Key);
        Assert.Equal("EventMessageFile", value.Name);
        Assert.Equal("[INSTALLDIR]DevolutionsAgent.exe", value.Value);
        Assert.Equal(win64, value.Win64);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
        Assert.False(value.ForceCreateOnInstall);
        Assert.False(value.ForceDeleteOnUninstall);
        Assert.Contains("Type=string", value.AttributesDefinition);
    }
}
