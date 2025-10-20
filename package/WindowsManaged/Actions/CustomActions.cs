using DevolutionsGateway.Configuration;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WixSharp;
using static DevolutionsGateway.Actions.WinAPI;
using File = System.IO.File;

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
                    if (string.IsNullOrEmpty(session.Get(GatewayProperties.certificatePassword)))
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
                            session.Get(GatewayProperties.certificatePassword));
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
                        command += $" -PublicKeyFile '{session.Get(GatewayProperties.publicKeyFile)}'";
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
                // TODO: constants
                command = $"Set-DGatewayUser -Username '{session.Get(GatewayProperties.webUsername)}' -Password '{session.Get(GatewayProperties.webPassword)}'";
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
        public static ActionResult EvaluateConfiguration(Session session)
        {
            ActionResult result = ActionResult.Success;
            Dictionary<string, (bool, FileAccess, Exception)> results = new Dictionary<string, (bool, FileAccess, Exception)>();

            uint read = FILE_READ_DATA /* aka FILE_LIST_DIRECTORY */ |
                        FILE_READ_EA | FILE_EXECUTE /* aka FILE_TRAVERSE */ |
                        FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
            uint write = read | FILE_WRITE_DATA /* aka FILE_ADD_FILE */ |
                         FILE_APPEND_DATA /* aka FILE_ADD_SUBDIRECTORY */ |
                         FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
            uint modify = write | DELETE;

            // Attempt to open a path with the specified access, as a means to check for permissions
            bool CanAccess(string path, bool isDirectory, uint desiredAccess)
            {
                using SafeFileHandle handle = CreateFile(
                    path, desiredAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero,
                    OPEN_EXISTING,
                    isDirectory ? FILE_FLAG_BACKUP_SEMANTICS : 0,
                    IntPtr.Zero);

                int lastError = Marshal.GetLastWin32Error();

                if (handle.IsInvalid)
                {
                    // ERROR_SUCCESS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED
                    if (!new[] {0, 2, 3, 5}.Contains(lastError))
                    {
                        session.Log($"CreateFile failed (error: {lastError})");
                        throw new Win32Exception(lastError);
                    }
                }

                return !handle.IsInvalid;
            }

            bool CheckAccess(string path, FileAccess desiredAccess, bool isDirectory)
            {
                if (string.IsNullOrEmpty(path))
                {
                    return true;
                }

                if (!Path.IsPathRooted(path))
                {
                    path = Path.Combine(ProgramDataDirectory, path);
                }

                uint accessMask;

                switch (desiredAccess)
                {
                    case FileAccess.Write:
                    {
                        accessMask = write;
                        break;
                    }
                    case FileAccess.Modify:
                    {
                        accessMask = modify;
                        break;
                    }
                    default:
                    {
                        accessMask = read;
                        break;
                    }
                }
                
                session.Log($"checking effective access {accessMask} to {path}");

                try
                {
                    if (CanAccess(path, isDirectory, accessMask))
                    {
                        results[path] = (true, desiredAccess, null);

                        return true;
                    }

                    results[path] = (false, desiredAccess, null);

                    session.Log($"effective access to {path} does not match desired access {accessMask}");
                    return false;

                }
                catch (Exception e)
                {
                    results[path] = (false, desiredAccess, e);

                    session.Log($"failed to check effective access to {path}: {e.Message}");
                    return false;
                }
            }

            IdentityReference account =
                new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null).Translate(typeof(NTAccount));

            try
            {
                string[] userDomain = account.Value.Split('\\');
                Gateway config = null;

                session.Log($"evaluating configuration as {account.Value}");

                using (Impersonation _ = new Impersonation(userDomain[1], userDomain[0], string.Empty))
                {
                    string configPath = Path.Combine(ProgramDataDirectory, GatewayConfigFile);

                    if (!TryReadGatewayConfig(session, configPath, out config, out Exception e))
                    {
                        results[configPath] = (false, FileAccess.Read, e);
                        session.Log("failed to load or parse the configuration file");
                    }

                    if (!CheckAccess(ProgramDataDirectory, FileAccess.Modify, true))
                    {
                        result = ActionResult.Failure;
                    }

                    List<string> readFiles = new()
                    {
                        config.DelegationPrivateKeyFile,
                        config.ProvisionerPublicKeyFile,
                        config.ProvisionerPrivateKeyFile,
                        config.TlsCertificateSource == "External" ? config.TlsCertificateFile : null,
                        config.TlsCertificateSource == "External" ? config.TlsPrivateKeyFile : null,
                    };

                    foreach (string readFile in readFiles.Where(x => !string.IsNullOrEmpty(x)))
                    {
                        if (!CheckAccess(readFile, FileAccess.Read, false))
                        {
                            result = ActionResult.Failure;
                        }
                    }

                    List<string> writeFiles = new()
                    {
                        (config.WebApp?.Enabled ?? false) && config.WebApp.Authentication == "Custom"
                            ? config.WebApp.UsersFile
                            : null,
                    };

                    foreach (string writeFile in writeFiles.Where(x => !string.IsNullOrEmpty(x)))
                    {
                        if (!CheckAccess(writeFile, FileAccess.Write, false))
                        {
                            result = ActionResult.Failure;
                        }
                    }
                }

                string jrlFile = config.JrlFile;

                if (!Path.IsPathRooted(jrlFile))
                {
                    jrlFile = Path.Combine(ProgramDataDirectory, jrlFile);
                }

                List<string> modifyFiles = new();

                try
                {
                    if (File.Exists(jrlFile))
                    {
                        modifyFiles.Add(jrlFile);
                    }
                }
                catch
                {
                }

                using (Impersonation _ = new Impersonation(userDomain[1], userDomain[0], string.Empty))
                {
                    string logDirectory = ProgramDataDirectory;
                    string logPattern = "gateway.*.log";

                    if (!string.IsNullOrEmpty(config.LogFile))
                    {
                        try
                        {
                            logDirectory = Path.GetDirectoryName(config.LogFile);
                            logPattern = $"{Path.GetFileName(config.LogFile)}.*.log";

                            if (!CheckAccess(logDirectory, FileAccess.Modify, true))
                            {
                                result = ActionResult.Failure;
                            }

                        }
                        catch (Exception e)
                        {
                            if (logDirectory is not null)
                            {
                                results[logDirectory] = (false, FileAccess.Modify, e);
                            }

                            session.Log($"unexpected error while checking configuration: {e}");
                            result = ActionResult.Failure;
                        }
                    }

                    if (!string.IsNullOrEmpty(logDirectory))
                    {
                        try
                        {
                            modifyFiles.AddRange(Directory.GetFiles(logDirectory, logPattern)
                                .OrderBy(x => new FileInfo(x).CreationTime)
                                .Take(10));
                        }
                        catch (Exception e)
                        {
                            session.Log($"unexpected error while checking configuration: {e}");
                            result = ActionResult.Failure;
                        }
                    }

                    foreach (string modifyFile in modifyFiles.Where(x => !string.IsNullOrEmpty(x)))
                    {
                        if (!CheckAccess(modifyFile, FileAccess.Modify, false))
                        {
                            result = ActionResult.Failure;
                        }
                    }
                }

                string recordingPath = config.RecordingPath;

                if (!Path.IsPathRooted(recordingPath))
                {
                    recordingPath = Path.Combine(ProgramDataDirectory, recordingPath);
                }

                if (Directory.Exists(recordingPath))
                {
                    using Impersonation _ = new Impersonation(userDomain[1], userDomain[0], string.Empty);
                    if (!CheckAccess(config.RecordingPath, FileAccess.Modify, true))
                    {
                        result = ActionResult.Failure;
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(recordingPath))
                        {
                            try
                            {
                                foreach (string recordingDir in Directory.GetDirectories(recordingPath)
                                             .OrderBy(x => new DirectoryInfo(x).CreationTime)
                                             .Take(10))
                                {
                                    if (!CheckAccess(recordingDir, FileAccess.Modify, true))
                                    {
                                        result = ActionResult.Failure;
                                    }
                                }
                            }
                            catch (Exception e)
                            {
                                results[recordingPath] = (false, FileAccess.Modify, e);
                                session.Log($"unexpected error while checking configuration: {e}");
                                result = ActionResult.Failure;
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                results["Not applicable"] = (false, FileAccess.None, e);
                session.Log($"unexpected error while checking configuration: {e}");
                result = ActionResult.Failure;
            }
            
            try
            {
                if (result == ActionResult.Failure)
                {
                    StringBuilder builder = new StringBuilder();

                    builder.AppendLine("<html>");
                    builder.AppendLine("<head></head>");
                    builder.AppendLine("<body>");
                    builder.AppendLine("<table style=\"width:100%\">");

                    builder.Append("<tr>");
                    builder.Append("<th>Path</th>");
                    builder.Append("<th>Account</th>");
                    builder.Append("<th>Access</th>");
                    builder.Append("<th>Success</th>");
                    builder.Append("<th>Error</th>");
                    builder.Append("</tr>");

                    foreach (string key in results.Keys)
                    {
                        builder.AppendLine("<tr>");
                        builder.Append($"<td>{key}</td>");
                        builder.Append($"<td>{account.Value}</td>");
                        builder.Append($"<td>{results[key].Item2.AsString()}</td>");
                        builder.Append($"<td>{results[key].Item1}</td>");
                        builder.Append($"<td>{results[key].Item3}</td>");
                        builder.AppendLine("</tr>");
                    }

                    builder.AppendLine("</table>");
                    builder.AppendLine("</body>");
                    builder.AppendLine("</html>");

                    string tempPath = session.Get(GatewayProperties.userTempPath);

                    if (string.IsNullOrEmpty(tempPath))
                    {
                        tempPath = Path.GetTempPath();
                    }

                    string reportPath = Path.Combine(tempPath, $"{session.Get(GatewayProperties.installId)}.{Includes.ERROR_REPORT_FILENAME}");

                    session.Log($"writing configuration issues to {reportPath}");

                    File.WriteAllText(reportPath, builder.ToString());
                }
            }
            catch (Exception e)
            {
                session.Log($"unexpected error while writing results: {e}");
            }

            return result;
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
                SetFileSecurity(session, ProgramDataDirectory, Includes.PROGRAM_DATA_SDDL);

                // Files created before NetworkService was granted access to the program data directory
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
        public static ActionResult SetUsersDatabaseFilePermissions(Session session)
        {
            try
            {
                SetFileSecurity(session, Path.Combine(ProgramDataDirectory, DefaultUsersFile), Includes.USERS_FILE_SDDL);
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

        internal static bool TryReadGatewayConfig(ILogger logger, string path, out Gateway gatewayConfig, out Exception error)
        {
            gatewayConfig = new Gateway();

            if (!File.Exists(path))
            {
                error = new FileNotFoundException(path);
                return false;
            }

            try
            {
                using StreamReader reader = new StreamReader(path);
                using JsonReader jsonReader = new JsonTextReader(reader);

                JsonSerializer serializer = new JsonSerializer();
                gatewayConfig = serializer.Deserialize<Gateway>(jsonReader);

                error = null;

                return true;
            }
            catch (Exception e)
            {
                logger.Log($"failed to load configuration file at {path}: {e}");
                error = e;
                return false;
            }
        }

        internal static bool TryReadGatewayConfig(Session session, string path, out Gateway gatewayConfig, out Exception error)
        {
            return TryReadGatewayConfig(LogDelegate.WithSession(session), path, out gatewayConfig, out error);
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

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            using HttpClient client = new HttpClient();
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
