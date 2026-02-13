using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
using System;
using System.Collections.Generic;
using System.Linq;
using WixSharp;
using Action = WixSharp.Action;

namespace DevolutionsAgent.Actions;

internal static class AgentActions
{
    // Immediate sequence

    // Set helper properties to determine what the installer is doing
    private static readonly SetPropertyAction isFirstInstall = new(
        new Id(nameof(isFirstInstall)), AgentProperties.firstInstall.Id, $"{true}", Return.check, When.After, Step.FindRelatedProducts,
        new Condition("NOT Installed AND NOT WIX_UPGRADE_DETECTED AND NOT WIX_DOWNGRADE_DETECTED"));

    private static readonly SetPropertyAction isUpgrading = new(
        new Id(nameof(isUpgrading)), AgentProperties.upgrading.Id, $"{true}", Return.check, When.After, new Step(isFirstInstall.Id),
        new Condition("WIX_UPGRADE_DETECTED AND NOT(REMOVE= \"ALL\")"));

    private static readonly SetPropertyAction isRemovingForUpgrade = new(
        new Id(nameof(isRemovingForUpgrade)), AgentProperties.removingForUpgrade.Id, Return.check, When.After, Step.RemoveExistingProducts,
        new Condition("(REMOVE = \"ALL\") AND UPGRADINGPRODUCTCODE"));

    private static readonly SetPropertyAction isUninstalling = new(
        new Id(nameof(isUninstalling)), AgentProperties.uninstalling.Id, $"{true}", Return.check, When.After, new Step(isUpgrading.Id),
        new Condition("Installed AND REMOVE AND NOT(WIX_UPGRADE_DETECTED OR UPGRADINGPRODUCTCODE)"));

    private static readonly SetPropertyAction isMaintenance = new(
        new Id(nameof(isMaintenance)), AgentProperties.maintenance.Id, $"{true}", Return.check, When.After, new Step(isUninstalling.Id),
        new Condition($"Installed AND NOT {AgentProperties.upgrading.Id} AND NOT {AgentProperties.uninstalling.Id} AND NOT UPGRADINGPRODUCTCODE"));

    private static readonly ManagedAction getNetFxInstalledVersion = new(
        new Id($"CA.{nameof(getNetFxInstalledVersion)}"),
        CustomActions.GetInstalledNetFx45Version,
        Return.check, When.After, Step.LaunchConditions, Condition.Always)
    {
        Execute = Execute.immediate,
    };

    private static readonly ManagedAction checkNetFxInstalledVersion = new(
        CustomActions.CheckInstalledNetFx45Version,
        Return.check, When.After, new Step(getNetFxInstalledVersion.Id), Condition.Always)
    {
        Execute = Execute.immediate,
    };

    private static readonly ManagedAction setInstallId = new(
        CustomActions.SetInstallId,
        Return.ignore, When.After, Step.InstallInitialize, Condition.Always)
    {
        Execute = Execute.immediate
    };

    /// <summary>
    /// Set the ARP installation location to the chosen install directory
    /// </summary>
    private static readonly SetPropertyAction setArpInstallLocation = new("ARPINSTALLLOCATION", $"[{AgentProperties.InstallDir}]")
    {
        Execute = Execute.immediate,
        Sequence = Sequence.InstallExecuteSequence,
        When = When.After,
        Step = Step.CostFinalize,
    };

    /// <summary>
    /// Read the previous installation directory from the registry into the `INSTALLDIR` property
    /// </summary>
    private static readonly ManagedAction getInstallDirFromRegistry = new(
        CustomActions.GetInstallDirFromRegistry,
        Return.ignore,
        When.Before, Step.LaunchConditions,
        new Condition(AgentProperties.InstallDir, string.Empty), // If the property hasn't already been explicitly set
        Sequence.InstallExecuteSequence);

    // Deferred sequence

    /// <summary>
    /// Create the path %ProgramData%\Devolutions\Agent if it does not exist
    /// </summary>
    /// <remarks>
    /// It's hard to tell the installer not to remove directories on uninstall. Since we want this folder to persist,
    /// it's easy to create it with a custom action than workaround Windows Installer.
    /// </remarks>
    private static readonly ElevatedManagedAction createProgramDataDirectory = new(
        new Id($"CA.{nameof(createProgramDataDirectory)}"),
        CustomActions.CreateProgramDataDirectory,
        Return.check,
        When.After, Step.CreateFolders,
        Condition.Always,
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Create the path %ProgramData%\Devolutions\Agent\Pedm and subfolders if they do not exist
    /// </summary>
    /// <remarks>
    /// It's hard to tell the installer not to remove directories on uninstall. Since we want this folder to persist,
    /// it's easy to create it with a custom action than workaround Windows Installer.
    /// </remarks>
    private static readonly ElevatedManagedAction createProgramDataPedmDirectories = new(
        new Id($"CA.{nameof(createProgramDataPedmDirectories)}"),
        CustomActions.CreateProgramDataPedmDirectories,
        Return.check,
        When.After, Step.CreateFolders,
        Features.PEDM_FEATURE.BeingInstall(),
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Set or reset the ACL on %ProgramData%\Devolutions\Agent
    /// </summary>
    private static readonly ElevatedManagedAction setProgramDataDirectoryPermissions = new(
        new Id($"CA.{nameof(setProgramDataDirectoryPermissions)}"),
        CustomActions.SetProgramDataDirectoryPermissions,
        Return.ignore,
        When.After, new Step(createProgramDataDirectory.Id),
        Condition.Always,
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
    };

    /// <summary>
    /// Set or reset the ACL on %ProgramData%\Devolutions\Agent\pedm
    /// </summary>
    private static readonly ElevatedManagedAction setProgramDataPedmDirectoryPermissions = new(
        new Id($"CA.{nameof(setProgramDataPedmDirectoryPermissions)}"),
        CustomActions.SetProgramDataPedmDirectoryPermissions,
        Return.ignore,
        When.After, new Step(createProgramDataPedmDirectories.Id),
        Condition.Always,
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
    };

    private static readonly ElevatedManagedAction cleanAgentConfigIfNeeded = new(
        new Id($"CA.{nameof(cleanAgentConfigIfNeeded)}"),
        CustomActions.CleanAgentConfig,
        Return.check,
        When.Before, Step.StartServices,
        AgentProperties.firstInstall.Equal(true) & AgentProperties.configureAgent.Equal(true),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
        UsesProperties = UseProperties(new [] { AgentProperties.installId })
    };

    private static readonly ElevatedManagedAction cleanAgentConfigIfNeededRollback = new(
        new Id($"CA.{nameof(cleanAgentConfigIfNeededRollback)}"),
        CustomActions.CleanAgentConfigRollback,
        Return.ignore,
        When.Before, new Step(cleanAgentConfigIfNeeded.Id),
        AgentProperties.firstInstall.Equal(true) & AgentProperties.configureAgent.Equal(true),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.rollback,
        Impersonate = false,
        UsesProperties = UseProperties(new[] { AgentProperties.installId })
    };

    /// <summary>
    /// Execute the installed DevolutionsAgent with the --config-init-only argument
    /// </summary>
    /// <remarks>
    /// Ensures a default configuration file is created
    /// </remarks>
    private static readonly WixQuietExecAction initAgentConfigIfNeeded = new(
        new Id($"CA.{nameof(initAgentConfigIfNeeded)}"),
        $"[{AgentProperties.InstallDir}]{Includes.EXECUTABLE_NAME}",
        "config init",
        Return.check,
        When.After, new Step(cleanAgentConfigIfNeeded.Id),
        AgentProperties.firstInstall.Equal(true) & AgentProperties.configureAgent.Equal(false),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
    };

    private static readonly ElevatedManagedAction shutdownDesktopApp = new(
        CustomActions.ShutdownDesktopApp,
        Return.ignore,
        When.Before, Step.RemoveFiles,
        Condition.Always,
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
    };

    private static readonly ManagedAction launchDesktopApp = new(
        CustomActions.LaunchDesktopApp,
        Return.ignore,
        When.After, Step.InstallFinalize,
        Condition.NOT_Installed & new Condition("(UILevel >= 3 OR WIXSHARP_MANAGED_UI_HANDLE <> \"\")"),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.immediate,
        Impersonate = true,
    };

    /// <summary>
    /// Start the installed DevolutionsAgent service
    /// </summary>
    /// <remarks>
    /// The service will be started if it's StartMode is "Automatic". May be overridden with the
    /// public property `NoStartService`.
    /// </remarks>
    private static readonly ElevatedManagedAction startAgentIfNeeded = new(
        CustomActions.StartAgentIfNeeded,
        Return.ignore,
        When.After, Step.StartServices,
        Condition.NOT_BeingRemoved,
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Attempt to restart the DevolutionsAgent service (if it's running) on maintenance installs
    /// </summary>
    /// <remarks>
    /// This was necessary in the old Wayk installer to reread configurations that may have been updated
    /// by the installer. It's usefulness os questionable with Devolutions Agent.
    /// </remarks>
    private static readonly ElevatedManagedAction restartAgent = new(
        CustomActions.RestartAgent,
        Return.ignore,
        When.After, Step.StartServices,
        AgentProperties.maintenance.Equal(true),
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Attempt to rollback any configuration files created
    /// </summary>
    private static readonly ElevatedManagedAction rollbackConfig = new(
        CustomActions.RollbackConfig,
        Return.ignore,
        When.Before, new Step(cleanAgentConfigIfNeeded.Id),
        AgentProperties.firstInstall.Equal(true),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.rollback,
    };

    private static readonly ElevatedManagedAction configureFeatures = new(
        CustomActions.ConfigureFeatures
    )
    {
        Id = new Id($"CA.{nameof(configureFeatures)}"),
        Sequence = Sequence.InstallExecuteSequence,
        Return = Return.check,
        Step = Step.StartServices,
        When = When.Before
    };

    private static readonly ElevatedManagedAction registerExplorerCommand = new(
        CustomActions.RegisterExplorerCommand
    )
    {
        Id = new Id($"CA.{nameof(registerExplorerCommand)}"),
        Feature = Features.PEDM_FEATURE,
        Sequence = Sequence.InstallExecuteSequence,
        Return = Return.check,
        Execute = Execute.deferred,
        Impersonate = false,
        Step = Step.InstallFiles,
        When = When.After,
        Condition = Features.PEDM_FEATURE.BeingInstall(),
    };

    private static readonly ElevatedManagedAction registerExplorerCommandRollback = new(
        CustomActions.UnregisterExplorerCommand
    )
    {
        Id = new Id($"CA.{nameof(registerExplorerCommandRollback)}"),
        Feature = Features.PEDM_FEATURE,
        Sequence = Sequence.InstallExecuteSequence,
        Return = Return.ignore,
        Execute = Execute.rollback,
        Step = new Step(registerExplorerCommand.Id),
        When = When.Before,
        Condition = Features.PEDM_FEATURE.BeingInstall(),
    };

    private static readonly ElevatedManagedAction unregisterExplorerCommand = new(
        CustomActions.UnregisterExplorerCommand
    )
    {
        Id = new Id($"CA.{nameof(unregisterExplorerCommand)}"),
        Feature = Features.PEDM_FEATURE,
        Sequence = Sequence.InstallExecuteSequence,
        Return = Return.ignore,
        Execute = Execute.deferred,
        Impersonate = false,
        Step = Step.RemoveFiles,
        When = When.Before,
        Condition = Features.PEDM_FEATURE.BeingUninstall(),
    };

    private static string UseProperties(IEnumerable<IWixProperty> properties)
    {
        if (!properties?.Any() ?? false)
        {
            return null;
        }

        if (properties.Any(p => p.Public && !p.Secure)) // Sanity check at project build time
        {
            throw new Exception($"property {properties.First(p => !p.Secure).Id} must be secure");
        }

        return string.Join(";", properties.Distinct().Select(x => $"{x.Id}=[{x.Id}]"));
    }

    internal static readonly Action[] Actions =
    {
        isFirstInstall,
        isUpgrading,
        isRemovingForUpgrade,
        isUninstalling,
        isMaintenance,
        setInstallId,
        getNetFxInstalledVersion,
        checkNetFxInstalledVersion,
        getInstallDirFromRegistry,
        setArpInstallLocation,
        configureFeatures,
        createProgramDataDirectory,
        setProgramDataDirectoryPermissions,
        createProgramDataPedmDirectories,
        setProgramDataPedmDirectoryPermissions,
        initAgentConfigIfNeeded,
        registerExplorerCommand,
        registerExplorerCommandRollback,
        unregisterExplorerCommand,
        cleanAgentConfigIfNeeded,
        cleanAgentConfigIfNeededRollback,
        shutdownDesktopApp,
        startAgentIfNeeded,
        launchDesktopApp,
        restartAgent,
        rollbackConfig,
    };
}
