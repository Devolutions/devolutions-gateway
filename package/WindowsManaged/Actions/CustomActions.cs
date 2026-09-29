using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WixSharp;
using static DevolutionsGateway.Actions.WinAPI;
using File = System.IO.File;
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace DevolutionsGateway.Actions
{
    public class CustomActions
    {
        private const string GatewayConfigFile = "gateway.json";

        private static readonly string[] ConfigFiles = new[] {
            GatewayConfigFile, 
            "server.crt", 
            "server.key", 
            "provisioner.pem",
            "provisioner.key"
        };

        private const int MAX_PATH = 260; // Defined in windows.h

        private static string ProgramDataDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Devolutions", "Gateway");

        public const string DefaultUsersFile = "users.txt";

        [CustomAction]
        public static ActionResult CheckInstalledNetFx45Version(Session session)
        {
            uint version = session.Get(GatewayProperties.netFx45Version);

            if (version < 394802) //4.6.2
            {
                session.Log($"netfx45 version: {version} is too old");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult CheckPowerShellVersion(Session _)
        {
            return CheckPowerShellVersion() ? ActionResult.Success : ActionResult.Failure;
        }

        [CustomAction]
        public static ActionResult CleanGatewayConfig(Session session)
        {
            if (!ConfigFiles.Any(x => File.Exists(Path.Combine(ProgramDataDirectory, x))))
            {
                return ActionResult.Success;
            }

            try
            {
                string zipFile = $"{Path.Combine(Path.GetTempPath(), session.Get(GatewayProperties.installId).ToString())}.zip";
                using ZipArchive archive = ZipFile.Open(zipFile, ZipArchiveMode.Create);

                WinAPI.MoveFileEx(zipFile, IntPtr.Zero, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);

                foreach (string configFile in ConfigFiles)
                {
                    string configFilePath = Path.Combine(ProgramDataDirectory, configFile);

                    if (File.Exists(configFilePath))
                    {
                        archive.CreateEntryFromFile(configFilePath, configFile);
                    }
                }

                foreach (string configFile in ConfigFiles)
                {
                    try
                    {
                        File.Delete(Path.Combine(ProgramDataDirectory, configFile));
                    }
                    catch
                    {
                    }
                }
            }
            catch (Exception e)
            {
                session.Log($"failed to archive existing config: {e}");
                return ActionResult.Failure;
            }


            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult CleanGatewayConfigRollback(Session session)
        {
            string zipFile = $"{Path.Combine(Path.GetTempPath(), session.Get(GatewayProperties.installId).ToString())}.zip";

            if (!File.Exists(zipFile))
            {
                return ActionResult.Success;
            }

            try
            {
                foreach (string configFile in ConfigFiles)
                {
                    try
                    {
                        File.Delete(Path.Combine(ProgramDataDirectory, configFile));
                    }
                    catch
                    {
                    }
                }

                using ZipArchive archive = ZipFile.Open(zipFile, ZipArchiveMode.Read);
                archive.ExtractToDirectory(ProgramDataDirectory);

                try
                {
                    File.Delete(zipFile);
                }
                catch
                {
                }
            }
            catch (Exception e)
            {
                session.Log($"failed to restore existing config: {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Failure;
        }

        [CustomAction]
        public static ActionResult ConfigureAccessUri(Session session)
        {
            string command;

            try
            {
                string scheme = session.Get(GatewayProperties.configureNgrok)
                    ? Constants.HttpsProtocol
                    : session.Get(GatewayProperties.accessUriScheme);

                string host = session.Get(GatewayProperties.configureNgrok)
                    ? session.Get(GatewayProperties.ngrokHttpDomain)
                    : session.Get(GatewayProperties.accessUriHost);

                uint port = session.Get(GatewayProperties.configureNgrok)
                    ? 443
                    : session.Get(GatewayProperties.accessUriPort);

                Uri uri = new($"{scheme}://{host}:{port}", UriKind.Absolute);

                command = string.Format(Constants.SetDGatewayHostnameCommandFormat, uri.Host);
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigureAccessUri)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureCertificate(Session session)
        {
            string command;

            try
            {
                Constants.CertificateMode mode = session.Get(GatewayProperties.certificateMode);

                if (session.Get(GatewayProperties.configureWebApp) && session.Get(GatewayProperties.generateCertificate))
                {
                    command = Constants.NewDGatewayCertificateCommand;
                }
                else if (mode == Constants.CertificateMode.External)
                {
                    string password = WixProperties.Decode(session, GatewayProperties.certificatePassword);

                    if (string.IsNullOrEmpty(password))
                    {
                        command = string.Format(
                            Constants.ImportDGatewayCertificateWithPrivateKeyCommandFormat,
                            session.Get(GatewayProperties.certificateFile),
                            session.Get(GatewayProperties.certificatePrivateKeyFile));
                    }
                    else
                    {
                        command = string.Format(
                            Constants.ImportDGatewayCertificateWithPasswordCommandFormat,
                            session.Get(GatewayProperties.certificateFile),
                            password.Replace("'", "''"));
                    }
                }
                else
                {
                    command = string.Format(
                        Constants.ImportDGatewayCertificateFromSystemFormat,
                        session.Get(GatewayProperties.certificateMode),
                        session.Get(GatewayProperties.certificateName),
                        session.Get(GatewayProperties.certificateStore),
                        session.Get(GatewayProperties.certificateLocation));
                }
                
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigureCertificate)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureInit(Session session)
        {
            string command;

            try
            {
                command = $"Set-DGatewayConfig -ConfigPath '{ProgramDataDirectory}' -Id '{Guid.NewGuid()}'";
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigureInit)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureListeners(Session session)
        {
            string command;

            try
            {
                string internalUrl = FormatHttpUrl(
                    session.Get(GatewayProperties.httpListenerScheme),
                    session.Get(GatewayProperties.httpListenerPort));
                string externalUrl = FormatHttpUrl(
                    session.Get(GatewayProperties.accessUriScheme),
                    session.Get(GatewayProperties.accessUriPort));

                command = string.Format(Constants.SetDGatewayListenersCommandFormat,
                    internalUrl, externalUrl,
                    session.Get(GatewayProperties.tcpListenerPort),
                    session.Get(GatewayProperties.tcpListenerPort));
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigureListeners)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureNgrokListeners(Session session)
        {
            string command;

            try
            {
                command = $"$Ngrok = New-DGatewayNgrokConfig -AuthToken '{session.Get(GatewayProperties.ngrokAuthToken)}'";
                command += $"; $HttpTunnel = New-DGatewayNgrokTunnel -Http -AllowCidrs @('0.0.0.0/0') -Domain '{session.Get(GatewayProperties.ngrokHttpDomain)}'";

                if (session.Get(GatewayProperties.ngrokEnableTcp))
                {
                    command += $"; $TcpTunnel = New-DGatewayNgrokTunnel -Tcp -AllowCidrs @('0.0.0.0/0') -RemoteAddr '{session.Get(GatewayProperties.ngrokRemoteAddress)}'";
                    command += "; $Ngrok.Tunnels = [PSCustomObject]@{'http-endpoint' = $HttpTunnel; 'tcp-endpoint' = $TcpTunnel}";
                }
                else
                {
                    command += "; $Ngrok.Tunnels = [PSCustomObject]@{'http-endpoint' = $HttpTunnel}";
                }

                command += "; Set-DGatewayConfig -Ngrok $Ngrok";
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigureNgrokListeners)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureAgentTunnel(Session session)
        {
            string command;

            try
            {
                command = $"$AgentTunnel = New-DGatewayAgentTunnelConfig -Enabled -ListenPort {session.Get(GatewayProperties.agentTunnelPort)}; Set-DGatewayConfig -AgentTunnel $AgentTunnel";
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigureAgentTunnel)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigurePublicKey(Session session)
        {
            string command;

            try
            {
                if (session.Get(GatewayProperties.configureWebApp) && session.Get(GatewayProperties.generateKeyPair))
                {
                    command = Constants.NewDGatewayProvisionerKeyPairCommand;
                }
                else
                {
                    command = Constants.ImportDGatewayProvisionerKeyCommand;

                    string dvlsUrl = session.Get(GatewayProperties.devolutionsServerUrl);
                    string publicKeyFile;

                    if (!string.IsNullOrEmpty(dvlsUrl))
                    {
                        if (!TryDownloadDvlsPublicKey(session, dvlsUrl, out publicKeyFile, out Exception e))
                        {
                            session.Log($"failed to download public key: {e}");

                            using Record record = new(3)
                            {
                                FormatString = "Failed to download public key from Devolutions Server: [1]",
                            };

                            record.SetString(1, e.ToString());
                            session.Message(InstallMessage.Error | (uint)MessageButtons.OK, record);

                            return ActionResult.Failure;
                        }
                    }
                    else
                    {
                        publicKeyFile = session.Get(GatewayProperties.publicKeyFile);
                    }

                    if (!string.IsNullOrEmpty(publicKeyFile))
                    {
                        command += $" -PublicKeyFile '{publicKeyFile}'";
                    }

                    if (!string.IsNullOrEmpty(session.Get(GatewayProperties.privateKeyFile)))
                    {
                        command += $" -PrivateKeyFile '{session.Get(GatewayProperties.privateKeyFile)}'";
                    }
                }
                
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigurePublicKey)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureWebApp(Session session)
        {
            string command;

            try
            {
                // TODO: constants
                command = "$WebApp = New-DGatewayWebAppConfig -Enabled $true";

                switch (session.Get(GatewayProperties.authenticationMode))
                {
                    case Constants.AuthenticationMode.None:
                    {
                        command += " -Authentication None";
                        break;
                    }

                    case Constants.AuthenticationMode.Custom:
                    {
                        command += " -Authentication Custom";
                        break;
                    }
                }
                
                command += "; Set-DGatewayConfig -WebApp $WebApp";

                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigurePublicKey)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult ConfigureWebAppUser(Session session)
        {
            string command;

            try
            {
                string password = WixProperties.Decode(session, GatewayProperties.webPassword);

                // TODO: constants
                command = $"Set-DGatewayUser -Username '{session.Get(GatewayProperties.webUsername)}' -Password '{password.Replace("'", "''")}'";
                command = FormatPowerShellCommand(session, command);
            }
            catch (Exception e)
            {
                session.Log($"command {nameof(ConfigurePublicKey)} execution failure: {e}");
                return ActionResult.Failure;
            }

            return ExecuteCommand(session, command);
        }

        [CustomAction]
        public static ActionResult CreateProgramDataDirectory(Session session)
        {
            string path = ProgramDataDirectory;

            try
            {
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }
            }
            catch (Exception e)
            {
                session.Log($"failed to evaluate or create path {path}: {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult GetInstallDirFromRegistry(Session session)
        {
            try
            {
                using RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64);
                using RegistryKey gatewayKey = localKey.OpenSubKey($@"Software\{Includes.VENDOR_NAME}\{Includes.SHORT_NAME}");
                string installDirValue = (string)gatewayKey.GetValue("InstallDir");

                if (string.IsNullOrEmpty(installDirValue))
                {
                    throw new Exception("failed to read installdir path from registry: path is null or empty");
                }

                session.Log($"read installdir path from registry: {installDirValue}");
                session[GatewayProperties.InstallDir] = installDirValue;

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to read installdir path from registry: {e}");
            }

            return ActionResult.Failure;
        }

        [CustomAction]
        public static ActionResult GetInstalledNetFx45Version(Session session)
        {
            if (!TryGetInstalledNetFx45Version(out uint version))
            {
                return ActionResult.Failure;
            }

            session.Log($"read netFxRelease path from registry: {version}");
            session.Set(GatewayProperties.netFx45Version, version);

            return ActionResult.Success;
        }
        
        [CustomAction]
        public static ActionResult GetPowerShellPathFromRegistry(Session session)
        {
            try
            {
                using RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64);
                using RegistryKey powerShellKey = localKey.OpenSubKey(@"Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell");

                string powershellPath = (string)powerShellKey?.GetValue("Path");

                if (string.IsNullOrEmpty(powershellPath))
                {
                    throw new Exception("failed to read powershell.exe path from registry: path is null or empty");
                }

                session.Log($"read powershell.exe path from registry: {powershellPath}");
                session.Set(GatewayProperties.powerShellPath, powershellPath);


                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to read powershell.exe path from registry: {e}");
            }

            return ActionResult.Failure;
        }

        [CustomAction]
        public static ActionResult OpenWebApp(Session session)
        {
            if (session.Get(GatewayProperties.configureWebApp))
            {
                try
                {
                    string scheme = session.Get(GatewayProperties.configureNgrok)
                        ? Constants.HttpsProtocol
                        : session.Get(GatewayProperties.httpListenerScheme);

                    string host = session.Get(GatewayProperties.configureNgrok)
                        ? session.Get(GatewayProperties.ngrokHttpDomain)
                        : session.Get(GatewayProperties.accessUriHost);

                    uint port = session.Get(GatewayProperties.configureNgrok)
                        ? 443
                        : session.Get(GatewayProperties.httpListenerPort);

                    Uri target;

                    if ((scheme == Constants.HttpProtocol && port == 80) ||
                        (scheme == Constants.HttpsProtocol && port == 443))
                    {
                        target = new Uri($"{scheme}://{host}", UriKind.Absolute);
                    }
                    else
                    {
                        target = new Uri($"{scheme}://{host}:{port}", UriKind.Absolute);
                    }

                    Process.Start(target.ToString());
                }
                catch
                {
                }
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult QueryGatewayStartupType(Session session)
        {
            if (!TryGetGatewayStartupType(session, out ServiceStartMode startMode))
            {
                return ActionResult.Failure;
            }

            session.Set(GatewayProperties.serviceStart, startMode);
            return ActionResult.Success;
        }

        /// <summary>
        /// Read the logon account of any existing Devolutions Gateway service into the `GatewayServiceAccount` property,
        /// so that upgrades preserve a custom service account unless one is explicitly specified.
        /// </summary>
        [CustomAction]
        public static ActionResult QueryGatewayServiceAccount(Session session)
        {
            try
            {
                string accountName = GatewayServiceAccount.QueryExistingAccount(Includes.SERVICE_NAME, LogDelegate.WithSession(session));
                if (accountName == null)
                {
                    session.Log("no existing service found; the service account defaults to NETWORK SERVICE");
                    return ActionResult.Success;
                }

                session.Set(GatewayProperties.existingServiceAccount, accountName);
                if (string.IsNullOrWhiteSpace(session.Get(GatewayProperties.serviceAccount)))
                {
                    session.Set(GatewayProperties.serviceAccount, accountName);
                }
            }
            catch (Exception e)
            {
                session.Log($"failed to query the existing service account: {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        /// <summary>
        /// Resolve and validate the `GatewayServiceAccount` property, and record its SID in `ServiceAccountSid`
        /// for the deferred actions that set permissions.
        /// </summary>
        /// <remarks>
        /// Runs before anything is changed on the system so that a failure leaves an existing installation intact.
        /// A password is only required when the service is (re)created, i.e. on a first install or an upgrade.
        /// On maintenance installs the existing service password is preserved by the service control manager.
        /// </remarks>
        [CustomAction]
        public static ActionResult ValidateServiceAccount(Session session)
        {
            ActionResult Fail(string msg)
            {
                session.Log(msg);
                using Record record = new(0) { FormatString = msg };
                session.Message(InstallMessage.Error | (uint)MessageButtons.OK, record);
                return ActionResult.Failure;
            }

            string accountName = session.Get(GatewayProperties.serviceAccount);
            string existingAccount = session.Get(GatewayProperties.existingServiceAccount);
            bool maintenance = !string.IsNullOrEmpty(session["Installed"]);

            if (maintenance && string.IsNullOrWhiteSpace(existingAccount) && string.IsNullOrWhiteSpace(accountName))
            {
                return Fail("The Gateway service is missing. Specify P.SERVICEACCOUNT explicitly to repair it.");
            }

            if (!GatewayServiceAccount.TryResolve(accountName, Includes.SERVICE_NAME, out GatewayServiceAccount account, out string error))
            {
                return Fail(error);
            }

            if (maintenance && !string.IsNullOrWhiteSpace(existingAccount))
            {
                if (!GatewayServiceAccount.TryResolve(existingAccount, Includes.SERVICE_NAME, out GatewayServiceAccount previous, out error))
                {
                    return Fail(error);
                }

                if (!previous.Sid.Equals(account.Sid))
                {
                    return Fail("Changing the service account during repair is not supported. Change the account during an upgrade instead.");
                }

                if (!string.IsNullOrEmpty(session.Get(GatewayProperties.servicePassword)))
                {
                    return Fail("Changing the service password during repair is not supported. Update the service credentials separately before repairing.");
                }
            }

            session.Log($"service account {account.Name} ({account.Sid}) is of kind {account.Kind}");
            session.Set(GatewayProperties.serviceAccount, account.Name);
            session.Set(GatewayProperties.serviceAccountSid, account.Sid.Value);

            string password = session.Get(GatewayProperties.servicePassword);
            bool serviceWillBeCreated = !maintenance || string.IsNullOrWhiteSpace(existingAccount);

            if (account.RequiresPassword)
            {
                if (string.IsNullOrEmpty(password))
                {
                    if (serviceWillBeCreated)
                    {
                        return Fail($"The service account '{account.Name}' requires a password. Specify it with the {GatewayProperties.servicePassword.Id} property, or use a passwordless account such as a group managed service account.");
                    }

                    session.Log("no password supplied; the existing service password is preserved");
                }
                else if (!account.TryValidatePassword(password, out error))
                {
                    return Fail(error);
                }
            }
            else if (!string.IsNullOrEmpty(password))
            {
                session.Log($"ignoring the password supplied for the passwordless account {account.Name}");
                session.Set(GatewayProperties.servicePassword, string.Empty);
            }

            try
            {
                bool configuring = session.Get(GatewayProperties.configureGateway) &&
                    (!maintenance || !string.IsNullOrEmpty(session["REINSTALL"]));
                if (configuring &&
                    !session.Get(GatewayProperties.configureNgrok) &&
                    session.Get(GatewayProperties.httpListenerScheme) == Constants.HttpsProtocol &&
                    !(session.Get(GatewayProperties.configureWebApp) && session.Get(GatewayProperties.generateCertificate)) &&
                    session.Get(GatewayProperties.certificateMode) == Constants.CertificateMode.System)
                {
                    CertificateStorePermissions.ValidateSelection(session.Get(GatewayProperties.certificateLocation));
                }

                string configPath = Path.Combine(ProgramDataDirectory, GatewayConfigFile);
                string preservedHash = File.Exists(configPath)
                    ? CertificateStorePermissions.ValidateExisting(
                        JObject.Parse(File.ReadAllText(configPath)), account.Sid, existingAccount, configuring)
                    : string.Empty;
                session.Set(GatewayProperties.preservedCertificateConfigHash, preservedHash);
                if (!string.IsNullOrEmpty(preservedHash))
                {
                    session.Log("retaining manually managed certificate-store configuration for the same service identity; certificate availability and private-key permissions are not verified");
                }
            }
            catch (Exception e)
            {
                return Fail($"The certificate-store configuration cannot be used by this installation: {e.Message}");
            }

            return ActionResult.Success;
        }

        /// <summary>
        /// Grant the service account the rights it needs to run the service. NETWORK SERVICE has them implicitly.
        /// </summary>
        [CustomAction]
        public static ActionResult ConfigureServiceAccount(Session session)
        {
            SecurityIdentifier serviceAccount = GetServiceAccountSid(session);

            if (serviceAccount.IsWellKnown(WellKnownSidType.NetworkServiceSid))
            {
                return ActionResult.Success;
            }

            try
            {
                AccountRights.Grant(serviceAccount, AccountRights.LogonAsService);
                session.Log($"granted {AccountRights.LogonAsService} to service account {serviceAccount}");
                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to grant {AccountRights.LogonAsService} to service account {serviceAccount}; the service may fail to start: {e}");
                return ActionResult.Failure;
            }
        }

        /// <summary>
        /// The SID recorded by <see cref="ValidateServiceAccount"/> for install and repair actions.
        /// </summary>
        private static SecurityIdentifier GetServiceAccountSid(Session session)
        {
            string sid = session.Get(GatewayProperties.serviceAccountSid);

            return new SecurityIdentifier(sid);
        }

        [CustomAction]
        public static ActionResult RestartGateway(Session session)
        {
            try
            {
                using ServiceManager sm = new(WinAPI.SC_MANAGER_CONNECT, LogDelegate.WithSession(session));

                if (!Service.TryOpen(
                        sm, Includes.SERVICE_NAME,
                        WinAPI.SERVICE_START | WinAPI.SERVICE_QUERY_STATUS | WinAPI.SERVICE_STOP,
                        out Service service, LogDelegate.WithSession(session)))
                {
                    return ActionResult.Failure;
                }

                using (service)
                {
                    service.Restart();
                }

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to restart service: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult RollbackConfig(Session session)
        {
            string path = ProgramDataDirectory;

            foreach (string configFile in ConfigFiles.Select(x => Path.Combine(path, x)))
            {
                try
                {
                    if (!File.Exists(configFile))
                    {
                        continue;
                    }

                    File.Delete(configFile);
                }
                catch (Exception e)
                {
                    session.Log($"failed to rollback file {configFile}: {e}");
                }
            }

            // Best effort, always return success
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult SetGatewayStartupType(Session session)
        {
            try
            {
                using ServiceManager sm = new(WinAPI.SC_MANAGER_CONNECT, LogDelegate.WithSession(session));

                if (!Service.TryOpen(sm, Includes.SERVICE_NAME, WinAPI.SERVICE_CHANGE_CONFIG, out Service service, LogDelegate.WithSession(session)))
                {
                    return ActionResult.Failure;
                }

                using (service)
                {
                    service.SetStartupType((ServiceStartMode)session.Get(GatewayProperties.serviceStart));
                }

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to set service startup type: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult EncodePropertyData(Session session)
        {
            foreach (IWixProperty property in GatewayProperties.Properties.Where(p => p.Encode))
            {
                if (property is not WixProperty<string> stringProperty)
                {
                    continue;
                }

                session.Log($"encoding property {property.Id}");
                WixProperties.Encode(session, stringProperty);
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult SetInstallId(Session session)
        {
            if (session.Get(GatewayProperties.installId) == Guid.Empty)
            {
                session.Set(GatewayProperties.installId, Guid.NewGuid());
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult SetProgramDataDirectoryPermissions(Session session)
        {
            try
            {
                SetFileSecurity(session, ProgramDataDirectory, Includes.ProgramDataSddl(GetServiceAccountSid(session)));

                // Files created before the service account was granted access to the program data directory
                // don't retroactively inherit the new ACE
                // We fix this by removing access rule protection on the files
                // and then reapplying the ACL
                DirectoryInfo dir = new DirectoryInfo(ProgramDataDirectory);

                foreach (FileInfo file in dir.GetFiles("*", SearchOption.AllDirectories))
                {
                    try
                    {
                        FileSecurity fileSecurity = file.GetAccessControl();
                        fileSecurity.SetAccessRuleProtection(false, false);
                        file.SetAccessControl(fileSecurity);
                    }
                    catch (Exception e)
                    {
                        session.Log($"failed to reset permissions on path {file.FullName}: {e}");
                        return ActionResult.Failure;
                    }
                }

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to set permissions: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult SetCertificatePrivateKeyPermissions(Session session)
        {
            try
            {
                string configPath = Path.Combine(ProgramDataDirectory, GatewayConfigFile);
                if (!File.Exists(configPath))
                {
                    if (!string.IsNullOrEmpty(session.Get(GatewayProperties.preservedCertificateConfigHash)))
                    {
                        throw new InvalidOperationException("the retained certificate-store configuration was removed after validation");
                    }
                    session.Log("no existing configuration; no certificate permissions to update");
                    return ActionResult.Success;
                }

                JObject config = JObject.Parse(File.ReadAllText(configPath));
                if (CertificateStorePermissions.PreserveExisting(config, session.Get(GatewayProperties.preservedCertificateConfigHash)))
                {
                    session.Log("leaving retained CurrentUser/CurrentService configuration and private-key ACLs unmanaged; no certificate lookup, permission grant, or verification was performed");
                    return ActionResult.Success;
                }
                if (!string.Equals((string)config["TlsCertificateSource"], "System", StringComparison.OrdinalIgnoreCase))
                {
                    return ActionResult.Success;
                }

                string subjectName = (string)config["TlsCertificateSubjectName"];
                string storeName = (string)config["TlsCertificateStoreName"] ?? "My";
                StoreLocation location = StoreLocation.LocalMachine;
                bool strictMode = (bool?)config["TlsVerifyStrict"] ?? false;
                if (string.IsNullOrWhiteSpace(subjectName))
                {
                    throw new InvalidOperationException("the system certificate subject is missing");
                }

                CertificateSelection.Result selection = CertificateSelection.Select(
                    location, storeName, subjectName, strictMode);

                if (selection.Selected == null)
                {
                    if (selection.AllFiltered)
                    {
                        session.Log($"found {selection.MatchCount} certificate(s) matching subject {subjectName} in {location}\\{storeName}, but all were filtered out by strict-mode prerequisites (issues: {selection.FilteredReasons})");
                    }
                    else
                    {
                        session.Log($"no certificate matching subject {subjectName} found in {location}\\{storeName}");
                    }
                    return ActionResult.Failure;
                }

                try
                {
                    X509Certificate2 certificate = selection.Selected;
                    session.Log($"selected certificate {certificate.Thumbprint} (NotAfter={certificate.NotAfter:o}) for subject {subjectName}");

                    SecurityIdentifier serviceAccount = GetServiceAccountSid(session);

                    if (PrivateKeyPermissions.HasReadPermission(certificate, serviceAccount))
                    {
                        session.Log($"service account {serviceAccount} already has Read access to the certificate's private key");
                        return ActionResult.Success;
                    }

                    if (PrivateKeyPermissions.TryGrantReadPermission(certificate, serviceAccount, out Exception grantError))
                    {
                        session.Log($"granted service account {serviceAccount} Read access to the certificate's private key");
                        return ActionResult.Success;
                    }

                    session.Log($"failed to grant service account {serviceAccount} Read access to the certificate's private key: {grantError}");
                    return ActionResult.Failure;
                }
                finally
                {
                    selection.Selected.Dispose();
                }
            }
            catch (Exception e)
            {
                session.Log($"unexpected error setting certificate private key permissions: {e}");
                return ActionResult.Failure;
            }

        }

        [CustomAction]
        public static ActionResult SetUsersDatabaseFilePermissions(Session session)
        {
            try
            {
                string path = Path.Combine(ProgramDataDirectory, DefaultUsersFile);
                if (!File.Exists(path))
                {
                    session.Log("no users database; no user file permissions to update");
                    return ActionResult.Success;
                }
                SetFileSecurity(session, path, Includes.UsersFileSddl(GetServiceAccountSid(session)));
                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to set permissions: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult StartGatewayIfNeeded(Session session)
        {
            try
            {
                using ServiceManager sm = new(WinAPI.SC_MANAGER_CONNECT);

                if (!Service.TryOpen(sm, Includes.SERVICE_NAME,
                        WinAPI.SERVICE_START | WinAPI.SERVICE_QUERY_CONFIG,
                        out Service service, LogDelegate.WithSession(session)))
                {
                    return ActionResult.Failure;
                }

                using (service)
                {
                    service.StartIfNeeded();
                }

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to start service: {e}");
                return ActionResult.Failure;
            }
        }

        public static bool CheckPowerShellVersion()
        {
            if (!TryGetPowerShellVersion(out Version powerShellVersion))
            {
                return false;
            }

            return powerShellVersion >= new Version(5, 1);
        }

        private static SafeFileHandle CreateSharedTempFile(Session session)
        {
            string tempPath = Path.GetTempPath();
            StringBuilder sb = new(MAX_PATH);

            if (WinAPI.GetTempFileName(tempPath, "DGW", 0, sb) == 0)
            {
                session.Log($"GetTempFileName failed (error: {Marshal.GetLastWin32Error()})");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            string tempFilePath = sb.ToString();

            WinAPI.SECURITY_ATTRIBUTES sa = new()
            {
                nLength = (uint)Marshal.SizeOf<WinAPI.SECURITY_ATTRIBUTES>(),
                lpSecurityDescriptor = IntPtr.Zero,
                bInheritHandle = true
            };

            using Buffer pSa = new(Marshal.SizeOf<WinAPI.SECURITY_ATTRIBUTES>());
            Marshal.StructureToPtr(sa, pSa, false);

            SafeFileHandle handle = WinAPI.CreateFile(tempFilePath,
                WinAPI.GENERIC_WRITE, WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE, pSa, WinAPI.CREATE_ALWAYS,
                WinAPI.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (handle.IsInvalid)
            {
                int errno = Marshal.GetLastWin32Error();
                session.Log($"CreateFile failed (error: {errno})");

                handle.Dispose();

                if (!WinAPI.DeleteFile(tempFilePath))
                {
                    session.Log($"DeleteFile failed (error: {Marshal.GetLastWin32Error()})");
                }

                throw new Win32Exception(errno);
            }

            if (!WinAPI.MoveFileEx(tempFilePath, IntPtr.Zero, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                session.Log($"MoveFileEx failed (error: {Marshal.GetLastWin32Error()})");
            }

            return handle;
        }

        private static uint ExecuteCommand(Session session, SafeFileHandle hTempFile, string command)
        {
            WinAPI.STARTUPINFO si = new()
            {
                cb = (uint)Marshal.SizeOf<WinAPI.STARTUPINFO>()
            };

            if (hTempFile.IsInvalid)
            {
                session.Log($"got an invalid file handle; command output will not be redirected");
            }
            else
            {
                si.dwFlags = WinAPI.STARTF_USESTDHANDLES;
                si.hStdInput = WinAPI.GetStdHandle(WinAPI.STD_INPUT_HANDLE);
                si.hStdOutput = hTempFile.DangerousGetHandle();
                si.hStdError = hTempFile.DangerousGetHandle();
            }

            using Buffer pSi = new(Marshal.SizeOf<WinAPI.STARTUPINFO>());
            Marshal.StructureToPtr(si, pSi, false);

            WinAPI.PROCESS_INFORMATION pi = new();

            using Buffer pPi = new(Marshal.SizeOf<WinAPI.PROCESS_INFORMATION>());
            Marshal.StructureToPtr(pi, pPi, false);

            if (session.Get(GatewayProperties.debugPowerShell))
            {
                session.Log($"Executing command: {command}");
            }

            if (!WinAPI.CreateProcess(null, command, IntPtr.Zero, IntPtr.Zero,
                    true, WinAPI.CREATE_NO_WINDOW, IntPtr.Zero, null, pSi, pPi))
            {
                session.Log($"CreateProcess failed (error: {Marshal.GetLastWin32Error()})");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            uint exitCode = 1;

            try
            {
                pi = Marshal.PtrToStructure<WinAPI.PROCESS_INFORMATION>(pPi);

                // Give the process reasonable time to finish, don't hang the installer
                if (WinAPI.WaitForSingleObject(pi.hProcess, (uint)TimeSpan.FromMinutes(1).TotalMilliseconds) != 0) // WAIT_OBJECT_0
                {
                    session.Log("timeout or error waiting for sub process");

                    if (!WinAPI.TerminateProcess(pi.hProcess, exitCode))
                    {
                        session.Log($"TerminateProcess failed (error: {Marshal.GetLastWin32Error()})");
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                if (!WinAPI.GetExitCodeProcess(pi.hProcess, out exitCode))
                {
                    session.Log($"GetExitCodeProcess failed (error: {Marshal.GetLastWin32Error()})");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (exitCode != 0)
                {
                    session.Log($"sub process returned a non-zero exit code: {exitCode})");
                }
            }
            finally
            {
                WinAPI.CloseHandle(pi.hProcess);
                WinAPI.CloseHandle(pi.hThread);
            }

            return exitCode;
        }

        private static ActionResult ExecuteCommand(Session session, string command)
        {
            using SafeFileHandle hTempFile = CreateSharedTempFile(session);

            uint exitCode;

            try
            {
                exitCode = ExecuteCommand(session, hTempFile, command);
            }
            catch (Exception e)
            {
                session.Log($"command execution failure: {e}");

                using Record record = new(3)
                {
                    FormatString = "Command execution failure: [1]",
                };

                record.SetString(1, e.ToString());
                session.Message(InstallMessage.Error | (uint)MessageButtons.OK, record);
                return ActionResult.Failure;
            }

            if (exitCode != 0)
            {
                StringBuilder tempFilePathBuilder = new(MAX_PATH);
                uint pathLength = WinAPI.GetFinalPathNameByHandle(hTempFile.DangerousGetHandle(), tempFilePathBuilder, MAX_PATH, 0);
                string result = "unknown";

                try
                {
                    if (pathLength is > 0 and < MAX_PATH)
                    {
                        string tempFilePath = tempFilePathBuilder.ToString().TrimStart('\\', '?');

                        using FileStream fileStream = new(tempFilePath, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite);
                        using StreamReader streamReader = new(fileStream);
                        result = streamReader.ReadToEnd();
                    }
                }
                catch (Exception e)
                {
                    session.Log($"error reading error from temp file: {e}");
                }
                
                using Record record = new(3)
                {
                    FormatString = "Command execution failure: [1]",
                };

                hTempFile.Close();
                
                record.SetString(1, result);
                session.Message(InstallMessage.Error | (uint)MessageButtons.OK, record);

                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        private static string FormatHttpUrl(string scheme, uint port)
        {
            string url = $"{scheme}://*";

            if ((scheme.Equals(Constants.HttpProtocol) && port != 80) || (scheme.Equals(Constants.HttpsProtocol) && port != 443))
            {
                url += $":{port}";
            }

            return url;
        }

        private static string FormatPowerShellCommand(Session session, string command)
        {
            return $"\"{session.Property(GatewayProperties.powerShellPath.Id)}\" -ep Bypass -Command \"& Import-Module '{session.Property(GatewayProperties.InstallDir)}PowerShell\\Modules\\DevolutionsGateway'; {command}\"";
        }
        
        public static void SetFileSecurity(Session session, string path, string sddl)
        {
            const uint sdRevision = 1;
            IntPtr pSd = new IntPtr();
            UIntPtr pSzSd = new UIntPtr();
           
            try
            {
                if (!WinAPI.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, sdRevision, out pSd, out pSzSd))
                {
                    session.Log($"ConvertStringSecurityDescriptorToSecurityDescriptorW failed (error: {Marshal.GetLastWin32Error()})");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!WinAPI.SetFileSecurityW(path, WinAPI.DACL_SECURITY_INFORMATION, pSd))
                {
                    session.Log($"SetFileSecurityW failed (error: {Marshal.GetLastWin32Error()})");
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (pSd != IntPtr.Zero)
                {
                    WinAPI.LocalFree(pSd);
                }
            }
        }

        private static bool TryGetGatewayStartupType(Session session, out ServiceStartMode startMode)
        {
            startMode = ServiceStartMode.Disabled;
            using ServiceManager sm = new(WinAPI.SC_MANAGER_CONNECT);

            if (!Service.TryOpen(sm, Includes.SERVICE_NAME, WinAPI.SERVICE_QUERY_CONFIG, out Service service))
            {
                return false;
            }

            using (service)
            {
                try
                {
                    startMode = service.GetStartupType();
                    return true;
                }
                catch (Exception e)
                {
                    session.Log($"failed to read service start type: {e}");
                    return false;
                }
            }
        }

        public static bool TryGetInstalledNetFx45Version(out uint version)
        {
            version = 0;

            try
            {
                // https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
                using RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64);
                using RegistryKey netFxKey = localKey.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full");

                if (netFxKey is null)
                {
                    // If the Full subkey is missing, then .NET Framework 4.5 or above isn't installed
                    return false;
                }

                version = Convert.ToUInt32(netFxKey.GetValue("Release"));

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryGetPowerShellVersion(out Version powerShellVersion)
        {
            powerShellVersion = new Version();
            string install = Registry.GetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\PowerShell\3", "Install", null)?.ToString();

            if (!install?.Equals("1") ?? false)
            {
                return false;
            }

            string version = Registry.GetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\PowerShell\3\PowerShellEngine",
                "PowerShellVersion", null)?.ToString();

            if (string.IsNullOrEmpty(version))
            {
                return false;
            }

            return Version.TryParse(version, out powerShellVersion);
        }

        private static bool TryDownloadDvlsPublicKey(Session session, string url, out string path, out Exception error)
        {
            path = null;
            error = null;

            if (!url.EndsWith("/"))
            {
                url += "/";
            }

            url += Constants.DVLSPublicKeyEndpoint;

            HttpClientHandler httpClientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    if (certificate is null)
                    {
                        session.Log("certificate trust verification failed due to invalid (null) certificate");
                        return false;
                    }

                    if (sslPolicyErrors == SslPolicyErrors.None)
                    {
                        session.Log("certificate trust verification succeeded (certificate is trusted)");
                        return true;
                    }

                    X509Certificate2 certificate2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

                    string exceptions = WixProperties.Decode(session, GatewayProperties.devolutionsServerCertificateExceptions);
                    CertificateExceptionStore store = CertificateExceptionStore.Deserialize(exceptions);

                    bool trust = store.IsTrusted(sender.RequestUri.Host, sender.RequestUri.Port, certificate2.Thumbprint);

                    session.Log($"certificate trust verification for {sender.RequestUri.Host}:{sender.RequestUri.Port} ({certificate2.Thumbprint}): {trust}");

                    return trust;
                },
                SslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12
            };

            using HttpClient client = new HttpClient(httpClientHandler, true);
            client.Timeout = TimeSpan.FromSeconds(5);

            TimeSpan backoff = TimeSpan.FromMilliseconds(500);
            Random rng = new Random();
            const int maxAttempts = 3;

            static bool ShouldRetry(HttpStatusCode code) =>
                code == HttpStatusCode.RequestTimeout || (int)code == 429 || (int)code >= 500;

            TimeSpan Jitter() => backoff + TimeSpan.FromMilliseconds(rng.Next(0, 250));

            TimeSpan ComputeDelay(HttpResponseMessage m)
            {
                if ((int)m.StatusCode == 429 && m.Headers.RetryAfter is { Delta: { } d })
                {
                    return d;
                }

                return Jitter();
            }

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                session.Log($"downloading public key from {url} attempt {attempt}");

                try
                {
                    using HttpResponseMessage response = client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();

                    if (ShouldRetry(response.StatusCode) && attempt < maxAttempts)
                    {
                        TimeSpan delay = ComputeDelay(response);
                        error = new Exception($"server returned {(int)response.StatusCode} {response.ReasonPhrase}, retrying in {delay.TotalMilliseconds}ms");
                        Thread.Sleep(delay);
                        backoff = TimeSpan.FromMilliseconds(backoff.TotalMilliseconds * 2);
                        continue;
                    }

                    response.EnsureSuccessStatusCode();

                    path = Path.GetTempFileName();
                    using Stream s = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();
                    using FileStream d = new FileStream(path, FileMode.Create, System.IO.FileAccess.Write, FileShare.None);
                    s.CopyTo(d);

                    session.Log($"downloaded public key to {path}");

                    try
                    {
                        WinAPI.MoveFileEx(path, IntPtr.Zero, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);
                    }
                    catch
                    {
                        // Cleanup, don't fail
                    }

                    return true;
                }
                catch (HttpRequestException ex) when (attempt < maxAttempts)
                {
                    TimeSpan delay = Jitter();
                    session.Log($"network error, retrying in {delay.TotalMilliseconds}ms ({ex.Message})");
                    Thread.Sleep(delay);
                    backoff = TimeSpan.FromMilliseconds(backoff.TotalMilliseconds * 2);
                }
                catch (IOException ex) when (attempt < maxAttempts)
                {
                    TimeSpan delay = Jitter();
                    session.Log($"io error, retrying in {delay.TotalMilliseconds}ms ({ex.Message})");
                    Thread.Sleep(delay);
                    backoff = TimeSpan.FromMilliseconds(backoff.TotalMilliseconds * 2);
                }
                catch (TaskCanceledException ex) when (attempt < maxAttempts)
                {
                    TimeSpan delay = Jitter();
                    session.Log($"timeout, retrying in {delay.TotalMilliseconds}ms ({ex.Message})");
                    Thread.Sleep(delay);
                    backoff = TimeSpan.FromMilliseconds(backoff.TotalMilliseconds * 2);
                }
                catch (Exception ex)
                {
                    error = ex;
                    return false;
                }
            }

            error ??= new Exception("all retries failed");

            return false;
        }
    }
}
