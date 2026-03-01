using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using System;
using System.Collections.Generic;
using System.Linq;
using WixSharp;
using Action = WixSharp.Action;

namespace DevolutionsGateway.Actions;

internal static class GatewayActions
{
    // Immediate sequence

    // Set helper properties to determine what the installer is doing
    private static readonly SetPropertyAction isFirstInstall = new(
        new Id(nameof(isFirstInstall)), GatewayProperties.firstInstall.Id, $"{true}", Return.check, When.After, Step.FindRelatedProducts,
        new Condition("NOT Installed AND NOT WIX_UPGRADE_DETECTED AND NOT WIX_DOWNGRADE_DETECTED"));

    private static readonly SetPropertyAction isUpgrading = new(
        new Id(nameof(isUpgrading)), GatewayProperties.upgrading.Id, $"{true}", Return.check, When.After, new Step(isFirstInstall.Id),
        new Condition("WIX_UPGRADE_DETECTED AND NOT(REMOVE= \"ALL\")"));

    private static readonly SetPropertyAction isRemovingForUpgrade = new(
        new Id(nameof(isRemovingForUpgrade)), GatewayProperties.removingForUpgrade.Id, Return.check, When.After, Step.RemoveExistingProducts,
        new Condition("(REMOVE = \"ALL\") AND UPGRADINGPRODUCTCODE"));

    private static readonly SetPropertyAction isUninstalling = new(
        new Id(nameof(isUninstalling)), GatewayProperties.uninstalling.Id, $"{true}", Return.check, When.After, new Step(isUpgrading.Id),
        new Condition("Installed AND REMOVE AND NOT(WIX_UPGRADE_DETECTED OR UPGRADINGPRODUCTCODE)"));

    private static readonly SetPropertyAction isMaintenance = new(
        new Id(nameof(isMaintenance)), GatewayProperties.maintenance.Id, $"{true}", Return.check, When.After, new Step(isUninstalling.Id),
        new Condition($"Installed AND NOT {GatewayProperties.upgrading.Id} AND NOT {GatewayProperties.uninstalling.Id} AND NOT UPGRADINGPRODUCTCODE"));

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

    private static readonly ManagedAction checkPowerShellVersion = new(
        CustomActions.CheckPowerShellVersion,
        Return.check, When.After, new Step(checkNetFxInstalledVersion.Id), Condition.Always)
    {
        Execute = Execute.immediate,
    };

    /// <summary>
    /// Get the path to Windows powershell.exe and read it into the `PowershellPath` property
    /// </summary>
    private static readonly ManagedAction getPowerShellPath = new(
        CustomActions.GetPowerShellPathFromRegistry,
        Return.check,
        When.After, new Step(checkPowerShellVersion.Id),
        Condition.Always,
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.immediate
    };

    private static readonly ManagedAction encodePropertyData = new(
        new Id($"CA.{nameof(encodePropertyData)}"),
        CustomActions.EncodePropertyData,
        Return.check, When.Before, Step.InstallInitialize, Condition.Always,
        Sequence.InstallExecuteSequence)
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
    private static readonly SetPropertyAction setArpInstallLocation = new("ARPINSTALLLOCATION", $"[{GatewayProperties.InstallDir}]")
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
        new Condition(GatewayProperties.InstallDir, string.Empty), // If the property hasn't already been explicitly set
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Query the start mode of any existing Devolutions Gateway service and read it into the `ServiceStart` property
    /// </summary>
    private static readonly ElevatedManagedAction queryGatewayStartupType = new(
        CustomActions.QueryGatewayStartupType,
        Return.ignore,
        When.Before, Step.RemoveExistingProducts,
        Condition.Always,
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.immediate,
        Impersonate = false
    };

    // Deferred sequence

    /// <summary>
    /// Create the path %programdata%\Devolutions\Gateway if it does not exist
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
    /// Set or reset the ACL on %programdata%\Devolutions\Gateway
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
    /// Set or reset the ACL on %programdata%\Devolutions\Gateway\users.txt
    /// </summary>
    private static readonly ElevatedManagedAction setUserDatabasePermissions = new(
            new Id($"CA.{nameof(setUserDatabasePermissions)}"),
            CustomActions.SetUsersDatabaseFilePermissions,
            Return.ignore,
            When.Before, Step.InstallFinalize,
            Condition.Always,
            Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
    };

    private static readonly ElevatedManagedAction cleanGatewayConfigIfNeeded = new(
        new Id($"CA.{nameof(cleanGatewayConfigIfNeeded)}"),
        CustomActions.CleanGatewayConfig,
        Return.check,
        When.Before, Step.StartServices,
        GatewayProperties.firstInstall.Equal(true) & GatewayProperties.configureGateway.Equal(true),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
        UsesProperties = UseProperties(new [] { GatewayProperties.installId })
    };
    
    private static readonly ElevatedManagedAction cleanGatewayConfigIfNeededRollback = new(
        new Id($"CA.{nameof(cleanGatewayConfigIfNeededRollback)}"),
        CustomActions.CleanGatewayConfigRollback,
        Return.ignore,
        When.Before, new Step(cleanGatewayConfigIfNeeded.Id),
        GatewayProperties.firstInstall.Equal(true) & GatewayProperties.configureGateway.Equal(true),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.rollback,
        Impersonate = false,
        UsesProperties = UseProperties(new[] { GatewayProperties.installId })
    };

    /// <summary>
    /// Execute the installed DevolutionsGateway with the --config-init-only argument
    /// </summary>
    /// <remarks>
    /// Ensures a default configuration file is created
    /// </remarks>
    private static readonly WixQuietExecAction initGatewayConfigIfNeeded = new(
        new Id($"CA.{nameof(initGatewayConfigIfNeeded)}"),
        $"[{GatewayProperties.InstallDir}]{Includes.EXECUTABLE_NAME}",
        "--config-init-only",
        Return.check,
        When.After, new Step(cleanGatewayConfigIfNeeded.Id),
        GatewayProperties.firstInstall.Equal(true) & GatewayProperties.configureGateway.Equal(false),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
    };

    /// <summary>
    /// Set the start mode of the installed Devolutions Gateway service
    /// </summary>
    /// <remarks>
    /// It's not possible to set this conditionally using WiX, so a custom action is used
    /// </remarks>
    private static readonly ElevatedManagedAction setGatewayStartupType = new(
        CustomActions.SetGatewayStartupType,
        Return.ignore,
        When.Before, Step.StartServices,
        Condition.Always,
        Sequence.InstallExecuteSequence)
    {
        UsesProperties = UseProperties(new[] { GatewayProperties.serviceStart })
    };

    /// <summary>
    /// Start the installed Devolutions Gateway service
    /// </summary>
    /// <remarks>
    /// The service will be started if it's StartMode is "Automatic". May be overridden with the
    /// public property `NoStartService`.
    /// </remarks>
    private static readonly ElevatedManagedAction startGatewayIfNeeded = new(
        CustomActions.StartGatewayIfNeeded,
        Return.ignore,
        When.After, Step.StartServices,
        Condition.NOT_BeingRemoved & GatewayProperties.noStartService.Equal(string.Empty),
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Attempt to restart the Devolutions Gateway service (if it's running) on maintenance installs
    /// </summary>
    /// <remarks>
    /// This was necessary in the old Wayk installer to reread configurations that may have been updated
    /// by the installer. It's usefulness os questionable with Devolutions Gateway.
    /// </remarks>
    private static readonly ElevatedManagedAction restartGateway = new(
        CustomActions.RestartGateway,
        Return.ignore,
        When.After, Step.StartServices,
        GatewayProperties.maintenance.Equal(true),
        Sequence.InstallExecuteSequence);

    /// <summary>
    /// Attempt to rollback any configuration files created
    /// </summary>
    private static readonly ElevatedManagedAction rollbackConfig = new(
        CustomActions.RollbackConfig,
        Return.ignore,
        When.Before, new Step(cleanGatewayConfigIfNeeded.Id),
        GatewayProperties.firstInstall.Equal(true),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.rollback,
    };

    /// <summary>
    /// </summary>
    private static readonly ElevatedManagedAction configureInit = BuildConfigureAction(
        $"CA.{nameof(configureInit)}",
        CustomActions.ConfigureInit,
        When.After, new Step(initGatewayConfigIfNeeded.Id),
        Enumerable.Empty<IWixProperty>(),
        Enumerable.Empty<Condition>());

    /// <summary>
    /// Configure the hostname using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configureAccessUri = BuildConfigureAction(
        $"CA.{nameof(configureAccessUri)}",
        CustomActions.ConfigureAccessUri,
        When.After, new Step(configureInit.Id),
        new IWixProperty[]
        {
            GatewayProperties.accessUriScheme,
            GatewayProperties.accessUriHost,
            GatewayProperties.accessUriPort,
            GatewayProperties.configureNgrok,
            GatewayProperties.ngrokHttpDomain,
        },
        Enumerable.Empty<Condition>());

    /// <summary>
    /// Configure the listeners using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configureListeners = BuildConfigureAction(
        $"CA.{nameof(configureListeners)}",
        CustomActions.ConfigureListeners,
        When.After, new Step(configureAccessUri.Id),
        new IWixProperty[]
        {
            GatewayProperties.accessUriScheme,
            GatewayProperties.accessUriPort,
            GatewayProperties.httpListenerScheme,
            GatewayProperties.httpListenerPort,
            GatewayProperties.tcpListenerPort,
        },
        new [] { GatewayProperties.configureNgrok.Equal(false) } );

    /// <summary>
    /// Configure the ngrok listeners using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configureNgrokListeners = BuildConfigureAction(
        $"CA.{nameof(configureNgrokListeners)}",
        CustomActions.ConfigureNgrokListeners,
        When.After, new Step(configureListeners.Id),
        new IWixProperty[]
        {
            GatewayProperties.ngrokAuthToken,
            GatewayProperties.ngrokHttpDomain,
            GatewayProperties.ngrokEnableTcp,
            GatewayProperties.ngrokRemoteAddress,
        },
        new[] { GatewayProperties.configureNgrok.Equal(true) });

    /// <summary>
    /// Configure the certificate using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configureCertificate = BuildConfigureAction(
        $"CA.{nameof(configureCertificate)}",
        CustomActions.ConfigureCertificate,
        When.After, new Step(configureNgrokListeners.Id),
        new IWixProperty[]
        {
            GatewayProperties.certificateMode,
            GatewayProperties.certificateFile,
            GatewayProperties.certificatePassword,
            GatewayProperties.certificatePrivateKeyFile,
            GatewayProperties.certificateLocation,
            GatewayProperties.certificateStore,
            GatewayProperties.certificateName,
            GatewayProperties.configureWebApp,
            GatewayProperties.generateCertificate,
        },
        new[]
        {
            GatewayProperties.httpListenerScheme.Equal(Constants.HttpsProtocol),
            GatewayProperties.configureNgrok.Equal(false)
        },
        hide: true // Don't print the custom action data to logs, it might contain a password
    );

    /// <summary>
    /// Configure the public key using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configurePublicKey = BuildConfigureAction(
        $"CA.{nameof(configurePublicKey)}",
        CustomActions.ConfigurePublicKey,
        When.After, new Step(configureCertificate.Id),
        new IWixProperty[]
        {
            GatewayProperties.publicKeyFile,
            GatewayProperties.privateKeyFile,
            GatewayProperties.configureWebApp,
            GatewayProperties.generateKeyPair,
            GatewayProperties.devolutionsServerUrl,
            GatewayProperties.devolutionsServerCertificateExceptions,
        },
        Enumerable.Empty<Condition>());


    /// <summary>
    /// Configure the standalone web application using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configureWebApp = BuildConfigureAction(
        $"CA.{nameof(configureWebApp)}",
        CustomActions.ConfigureWebApp,
        When.After, new Step(configurePublicKey.Id),
        new IWixProperty[]
        {
            GatewayProperties.authenticationMode,
        },
        new[] { GatewayProperties.configureWebApp.Equal(true) }
    );

    /// <summary>
    /// Configure the standalone web application default user using PowerShell
    /// </summary>
    private static readonly ElevatedManagedAction configureWebAppUser = BuildConfigureAction(
        $"CA.{nameof(configureWebAppUser)}",
        CustomActions.ConfigureWebAppUser,
        When.After, new Step(configurePublicKey.Id),
        new IWixProperty[]
        {
            GatewayProperties.webUsername,
            GatewayProperties.webPassword,
        },
        new[]
        {
            GatewayProperties.configureWebApp.Equal(true),
            GatewayProperties.authenticationMode.Equal(Constants.AuthenticationMode.Custom)
        },
        hide: true // Don't print the custom action data to logs, it contains a password
    );

    private static string UseProperties(IEnumerable<IWixProperty> properties)
    {
        if (properties?.Any() != true)
        {
            return null;
        }

        if (properties.Any(p => p.Public && !p.Secure)) // Sanity check at project build time
        {
            throw new Exception($"property {properties.First(p => !p.Secure).Id} must be secure");
        }

        return string.Join(";", properties
           .Distinct()
           .Select(p => p.Encode ? p.EncodedId() : p.Id)
           .Select(id => $"{id}=[{id}]"));
    }

    /// <summary>
    /// Helper method to build "Configure*" actions
    /// </summary>
    private static ElevatedManagedAction BuildConfigureAction(
        string id,
        CustomActionMethod method,
        When when,
        Step step,
        IEnumerable<IWixProperty> usesProperties,
        IEnumerable<Condition> additionalConditions,
        bool hide = false)
    {
        List<IWixProperty> properties = usesProperties.Distinct().ToList();
        properties.Add(GatewayProperties.powerShellPath);
        properties.Add(GatewayProperties.debugPowerShell);

        List<Condition> conditions = additionalConditions.Distinct().ToList();
        conditions.Add(new Condition("NOT Installed OR REINSTALL"));
        conditions.Add(GatewayProperties.configureGateway.Equal(true));

        Condition condition = new(string.Join(" AND ", conditions.Select(x => $"({x})")));

        ElevatedManagedAction action = new(
            new Id(id), method, Return.check, when, step, condition, Sequence.InstallExecuteSequence)
        {
            UsesProperties = UseProperties(properties),
            AttributesDefinition = $"HideTarget={(hide ? "yes" : "no")}"
        };

        return action;
    }

    private static readonly ElevatedManagedAction evaluateConfiguration = new(
        new Id($"CA.{nameof(evaluateConfiguration)}"),
        CustomActions.EvaluateConfiguration,
        Return.ignore,
        When.After, new Step(setUserDatabasePermissions.Id),
        GatewayProperties.uninstalling.Equal(false),
        Sequence.InstallExecuteSequence)
    {
        Execute = Execute.deferred,
        Impersonate = false,
        UsesProperties = UseProperties(new IWixProperty[] { GatewayProperties.installId, GatewayProperties.userTempPath })
    };

    internal static readonly Action[] Actions =
    {
        isFirstInstall,
        isUpgrading,
        isRemovingForUpgrade,
        isUninstalling,
        isMaintenance,
        encodePropertyData,
        setInstallId,
        getNetFxInstalledVersion,
        checkNetFxInstalledVersion,
        checkPowerShellVersion,
        getPowerShellPath,
        getInstallDirFromRegistry,
        setArpInstallLocation,
        createProgramDataDirectory,
        setProgramDataDirectoryPermissions,
        setUserDatabasePermissions,
        cleanGatewayConfigIfNeeded,
        cleanGatewayConfigIfNeededRollback,
        initGatewayConfigIfNeeded,
        queryGatewayStartupType,
        setGatewayStartupType,
        startGatewayIfNeeded,
        restartGateway,
        rollbackConfig,
        configureInit,
        configureAccessUri,
        configureListeners,
        configureCertificate,
        configureNgrokListeners,
        configurePublicKey,
        configureWebApp,
        configureWebAppUser,
        evaluateConfiguration,
    };
}
