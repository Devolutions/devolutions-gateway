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
    // now-package-broker/src/audit.rs). Windows resolves that source to the messages compiled into
    // DevolutionsAgent.exe only from a registry source key named exactly after the runtime source
    // name, with EventMessageFile pointing at the executable carrying the message table. A
    // regression here fails nothing at build time: the sink degrades to a no-op on initialization
    // failure and only logs a tracing error, so the release build would silently lose those events.
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
        // 64-bit readers only see the source if the value lands in the matching registry view.
        Assert.Equal(win64, value.Win64);
        // Registered on install and removed on uninstall, without clobbering a source that an
        // administrator or another product owns.
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
        Assert.False(value.ForceCreateOnInstall);
        Assert.False(value.ForceDeleteOnUninstall);
        // EventMessageFile has to be REG_SZ, since a REG_MULTI_SZ value is not read as a path.
        Assert.Contains("Type=string", value.AttributesDefinition);
    }
}
