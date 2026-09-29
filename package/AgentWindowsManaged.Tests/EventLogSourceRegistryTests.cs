using System;
using System.Reflection;

using WixSharp;

using Xunit;

namespace DevolutionsAgent.Installer.Tests;

public sealed class EventLogSourceRegistryTests
{
    // The Agent's policy audit trail is only readable if the installer declares the Windows Event
    // Log source, so this test pins that declaration against regression.
    //
    // The broker's audit sink writes under the source name "Devolutions Agent" (WinEvent::new in
    // now-package-broker/src/audit.rs), which only calls RegisterEventSourceW. That call succeeds
    // without a registry source key, so the event still reaches the Application log; what the key
    // provides is the message template. Without a source key named exactly after the runtime source
    // name, with EventMessageFile pointing at the executable carrying the message table, Windows
    // cannot resolve the template and the entry shows the raw event id and its insertion strings
    // instead of the description compiled into DevolutionsAgent.exe.
    //
    // Nothing fails at build time when the declaration regresses, so this test is what keeps it in
    // step with the runtime source name.
    //
    // This asserts the declared value only. It does not build or install an MSI, so it does not
    // validate the WiX pipeline or the [INSTALLDIR] substitution.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SourceUsesNativeMsiRegistryLifecycle(bool win64)
    {
        // The installer is an application, referenced for its build output only, so it is loaded by
        // name and the helper is reached through reflection.
        Type program = System.Reflection.Assembly.Load("DevolutionsAgent").GetType("DevolutionsAgent.Program", throwOnError: true);
        MethodInfo method = program.GetMethod(
            "CreateEventLogSourceRegistryValue",
            BindingFlags.Static | BindingFlags.NonPublic);
        RegValue value = Assert.IsType<RegValue>(method.Invoke(null, [win64]));

        Assert.Equal(RegistryHive.LocalMachine, value.Root);
        // The key has to match the source name used by the audit sink, or the message is unresolved.
        Assert.Equal(@"SYSTEM\CurrentControlSet\Services\EventLog\Application\Devolutions Agent", value.Key);
        Assert.Equal("EventMessageFile", value.Name);
        Assert.Equal("[INSTALLDIR]DevolutionsAgent.exe", value.Value);
        // Pins the architecture flag the installer passes to the MSI component. HKLM\SYSTEM is
        // shared between the WOW64 registry views, so this is not what makes a 64-bit reader see
        // the source.
        Assert.Equal(win64, value.Win64);
        // Registered on install and removed on uninstall through the component lifecycle, which
        // leaves the source key itself alone. createAndRemoveOnUninstall would delete the whole key
        // on uninstall, including anything an administrator or another installer put there.
        Assert.Equal(RegistryKeyAction.create, value.RegistryKeyAction);
        Assert.False(value.ForceCreateOnInstall);
        Assert.False(value.ForceDeleteOnUninstall);
        // EventMessageFile has to be REG_SZ, since a REG_MULTI_SZ value is not read as a path.
        Assert.Contains("Type=string", value.AttributesDefinition);
    }
}
