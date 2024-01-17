using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using System;
using System.Collections.Generic;
using System.Linq;
using WixSharp;
using Action = WixSharp.Action;

namespace DevolutionsGateway.Actions
{
    internal static class GatewayActions
    {
        // Immediate sequence

        // Set helper properties to determine what the installer is doing
        private static readonly SetPropertyAction isFirstInstall = new(
            new Id(nameof(isFirstInstall)), GatewayProperties._FirstInstall.Id, $"{true}", Return.check, When.After, Step.FindRelatedProducts,
            new Condition("NOT Installed AND NOT WIX_UPGRADE_DETECTED AND NOT WIX_DOWNGRADE_DETECTED"));

        private static readonly SetPropertyAction isUpgrading = new(
            new Id(nameof(isUpgrading)), GatewayProperties._Upgrading.Id, $"{true}", Return.check, When.After, new Step(isFirstInstall.Id),
            new Condition("WIX_UPGRADE_DETECTED AND NOT(REMOVE= \"ALL\")"));

        private static readonly SetPropertyAction isRemovingForUpgrade = new(
            new Id(nameof(isRemovingForUpgrade)), GatewayProperties._RemovingForUpgrade.Id, Return.check, When.After, Step.RemoveExistingProducts,
            new Condition("(REMOVE = \"ALL\") AND UPGRADINGPRODUCTCODE"));

        private static readonly SetPropertyAction isUninstalling = new(
            new Id(nameof(isUninstalling)), GatewayProperties._Uninstalling.Id, $"{true}", Return.check, When.After, new Step(isUpgrading.Id),
            new Condition("Installed AND REMOVE AND NOT(WIX_UPGRADE_DETECTED OR UPGRADINGPRODUCTCODE)"));

        private static readonly SetPropertyAction isMaintenance = new(
            new Id(nameof(isMaintenance)), GatewayProperties._Maintenance.Id, $"{true}", Return.check, When.After, new Step(isUninstalling.Id),
            new Condition($"Installed AND NOT {GatewayProperties._Upgrading.Id} AND NOT {GatewayProperties._Uninstalling.Id} AND NOT UPGRADINGPRODUCTCODE"));

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

        /// <summary>
        /// Set the ARP installation location to the chosen install directory
        /// </summary>
        private static readonly SetPropertyAction setArpInstallLocation = new("ARPINSTALLLOCATION", $"[{GatewayProperties.InstallDir}]")
        {
            Condition = Condition.Always
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
        /// Get the path to Windows powershell.exe and read it into the `PowershellPath` property
        /// </summary>
        private static readonly ManagedAction getPowerShellPath = new(
            CustomActions.GetPowerShellPathFromRegistry,
            Return.check,
            When.Before, Step.LaunchConditions,
            Condition.Always,
            Sequence.InstallExecuteSequence)
        {
            Execute = Execute.immediate
        };

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
        private static readonly WixQuietExecAction setProgramDataDirectoryPermissions = new(
            "cmd.exe",
            $"/c ECHO Y| \"%windir%\\System32\\cacls.exe\" \"%ProgramData%\\{Includes.VENDOR_NAME}\\{Includes.SHORT_NAME}\" /S:{Includes.PROGRAM_DATA_SDDL} /C /t",
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
        private static readonly WixQuietExecAction setUserDatabasePermissions = new(
            "cmd.exe",
            $"/c ECHO Y| \"%windir%\\System32\\cacls.exe\" \"%ProgramData%\\{Includes.VENDOR_NAME}\\{Includes.SHORT_NAME}\\users.txt\" /S:{Includes.USERS_FILE_SDDL} /C",
            Return.ignore,
            When.Before, Step.InstallFinalize,
            Condition.Always,
            Sequence.InstallExecuteSequence)
        {
            Execute = Execute.deferred,
            Impersonate = false,
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
            When.Before, Step.StartServices,
            new Condition(GatewayProperties._FirstInstall.Id, true.ToString()),
            Sequence.InstallExecuteSequence)
        {
            Execute = Execute.deferred,
            Impersonate = false,
        };

        /// <summary>
        /// Open the installed web application in the user's system browser
        /// </summary>
        /// <remarks>
        /// Shouldn't be done on silent installs, but we only support customization by UI currently
        /// </remarks>
        private static readonly ManagedAction openWebApp = new(
            CustomActions.OpenWebApp,
            Return.ignore, When.After,
            Step.InstallFinalize,
            new Condition(GatewayProperties._FirstInstall.Id, true.ToString()))
        {
            UsesProperties = UseProperties(new IWixProperty[]
            {
                GatewayProperties._ConfigureWebApp,
                GatewayProperties._HttpListenerScheme,
                GatewayProperties._HttpListenerPort,
                GatewayProperties._AccessUriHost,
            })
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
            UsesProperties = UseProperties(new[] { GatewayProperties._ServiceStart })
        };

        /// <summary>
        /// Start the installed Devolutions Gateway service
        /// </summary>
        /// <remarks>
        /// The service will be started if it's StartMode is "Automatic". May be overridden with the
        /// user property `NoStartService`.
        /// </remarks>
        private static readonly ElevatedManagedAction startGatewayIfNeeded = new(
            CustomActions.StartGatewayIfNeeded,
            Return.ignore,
            When.After, Step.StartServices,
            $"{Condition.NOT_BeingRemoved} AND ({GatewayProperties._NoStartService.Id} = \"\")",
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
            new Condition(GatewayProperties._Maintenance.Id, true.ToString()),
            Sequence.InstallExecuteSequence);

        /// <summary>
        /// Attempt to rollback any configuration files created
        /// </summary>
        private static readonly ElevatedManagedAction rollbackConfig = new(
            CustomActions.RollbackConfig,
            Return.ignore,
            When.Before, new Step(initGatewayConfigIfNeeded.Id),
            new Condition(GatewayProperties._FirstInstall.Id, true.ToString()),
            Sequence.InstallExecuteSequence)
        {
            Execute = Execute.rollback,
        };

        /// <summary>
        /// Configure the hostname using PowerShell
        /// </summary>
        private static readonly ElevatedManagedAction configureAccessUri = BuildConfigureAction(
            $"CA.{nameof(configureAccessUri)}",
            CustomActions.ConfigureAccessUri,
            When.After, new Step(initGatewayConfigIfNeeded.Id),
            new IWixProperty[]
            {
                    GatewayProperties._AccessUriScheme,
                    GatewayProperties._AccessUriHost,
                    GatewayProperties._AccessUriPort,
            });

        /// <summary>
        /// Configure the listeners using PowerShell
        /// </summary>
        private static readonly ElevatedManagedAction configureListeners = BuildConfigureAction(
            $"CA.{nameof(configureListeners)}",
            CustomActions.ConfigureListeners,
            When.After, new Step(configureAccessUri.Id),
            new IWixProperty[]
            {
                    GatewayProperties._AccessUriScheme,
                    GatewayProperties._AccessUriPort,
                    GatewayProperties._HttpListenerScheme,
                    GatewayProperties._HttpListenerPort,
                    GatewayProperties._TcpListenerPort,
            });

        /// <summary>
        /// Configure the certificate using PowerShell
        /// </summary>
        private static readonly ElevatedManagedAction configureCertificate = BuildConfigureAction(
            $"CA.{nameof(configureCertificate)}",
            CustomActions.ConfigureCertificate,
            When.After, new Step(configureListeners.Id),
            new IWixProperty[]
            {
                    GatewayProperties._CertificateMode,
                    GatewayProperties._CertificateFile,
                    GatewayProperties._CertificatePassword,
                    GatewayProperties._CertificatePrivateKeyFile,
                    GatewayProperties._CertificateLocation,
                    GatewayProperties._CertificateStore,
                    GatewayProperties._CertificateName,
                    GatewayProperties._ConfigureWebApp,
                    GatewayProperties._GenerateCertificate,
            },
            attributesDefinition: "HideTarget=yes", // Don't print the custom action data to logs, it might contain a password
            additionalCondition: $" AND ({new Condition(GatewayProperties._HttpListenerScheme.Id, Constants.HttpsProtocol)})"); // Only if the HTTP listener uses https

        /// <summary>
        /// Configure the public key using PowerShell
        /// </summary>
        private static readonly ElevatedManagedAction configurePublicKey = BuildConfigureAction(
            $"CA.{nameof(configurePublicKey)}",
            CustomActions.ConfigurePublicKey,
            When.After, new Step(configureCertificate.Id),
            new IWixProperty[]
            {
                GatewayProperties._PublicKeyFile,
                GatewayProperties._PrivateKeyFile,
                GatewayProperties._ConfigureWebApp,
                GatewayProperties._GenerateKeyPair,
            });
            

        /// <summary>
        /// Configure the standalone web application using PowerShell
        /// </summary>
        private static readonly ElevatedManagedAction configureWebApp = BuildConfigureAction(
            $"CA.{nameof(configureWebApp)}",
            CustomActions.ConfigureWebApp,
            When.After, new Step(configurePublicKey.Id),
            new IWixProperty[]
            {
                GatewayProperties._AuthenticationMode,
            }, 
            additionalCondition: $" AND ({GatewayProperties._ConfigureWebApp.Id} = \"{true}\")");

        /// <summary>
        /// Configure the standalone web application default user using PowerShell
        /// </summary>
        private static readonly ElevatedManagedAction configureWebAppUser = BuildConfigureAction(
            $"CA.{nameof(configureWebAppUser)}",
            CustomActions.ConfigureWebAppUser,
            When.After, new Step(configurePublicKey.Id),
            new IWixProperty[]
            {
                GatewayProperties._WebUsername,
                GatewayProperties._WebPassword,
            },
            attributesDefinition: "HideTarget=yes", // Don't print the custom action data to logs, it contains a password
            additionalCondition: $" AND ({GatewayProperties._ConfigureWebApp.Id} = \"{true}\") AND ({GatewayProperties._AuthenticationMode.Id} = \"{Constants.AuthenticationMode.Custom}\")");

        private static string UseProperties(IEnumerable<IWixProperty> properties)
        {
            if (!properties?.Any() ?? false)
            {
                return null;
            }

            if (properties.Any(p => !p.Secure)) // Sanity check at project build time
            {
                throw new Exception($"property {properties.First(p => !p.Secure).Id} must be secure");
            }

            return string.Join(";", properties.Distinct().Select(x => $"{x.Id}=[{x.Id}]"));
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
            string attributesDefinition = null,
            Condition additionalCondition = null)
        {
            List<IWixProperty> properties = usesProperties.Distinct().ToList();
            properties.Add(GatewayProperties._PowerShellPath);

            ElevatedManagedAction action = new ElevatedManagedAction(
                new Id(id), method, Return.check, when, step,
                $"(NOT Installed OR REINSTALL) AND ({GatewayProperties._ConfigureGateway.Id} = \"{true}\")",
                Sequence.InstallExecuteSequence)
            {
                UsesProperties = UseProperties(properties),
            };

            if (!string.IsNullOrEmpty(attributesDefinition))
            {
                action.AttributesDefinition = attributesDefinition;
            }

            if (additionalCondition is not null)
            {
                action.Condition += additionalCondition;
            }

            return action;
        }

        internal static readonly Action[] Actions =
        {
            isFirstInstall,
            isUpgrading,
            isRemovingForUpgrade,
            isUninstalling,
            isMaintenance,
            getNetFxInstalledVersion,
            checkNetFxInstalledVersion,
            getPowerShellPath,
            getInstallDirFromRegistry,
            setArpInstallLocation,
            createProgramDataDirectory,
            setProgramDataDirectoryPermissions,
            setUserDatabasePermissions,
            initGatewayConfigIfNeeded,
            openWebApp,
            queryGatewayStartupType,
            setGatewayStartupType,
            startGatewayIfNeeded,
            restartGateway,
            rollbackConfig,
            configureAccessUri,
            configureListeners,
            configureCertificate,
            configurePublicKey,
            configureWebApp,
            configureWebAppUser,
        };
    }
}
