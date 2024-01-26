using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using WixSharp;
using File = System.IO.File;

namespace DevolutionsGateway.Actions
{
    public class CustomActions
    {
        private static readonly string[] ConfigFiles = new[] {
            "gateway.json", 
            "server.crt", 
            "server.key", 
            "provisioner.pem",
            "provisioner.key"
        };

        private const int MAX_PATH = 260; // Defined in windows.h

        private static string ProgramDataDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Devolutions", "Gateway");

        [CustomAction]
        public static ActionResult CheckInstalledNetFx45Version(Session session)
        {
            uint version = session.Get(GatewayProperties._NetFx45Version);

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
                string zipFile = $"{Path.Combine(Path.GetTempPath(), session.Get(GatewayProperties._InstallId).ToString())}.zip";
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
            string zipFile = $"{Path.Combine(Path.GetTempPath(), session.Get(GatewayProperties._InstallId).ToString())}.zip";

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
                string scheme = session.Get(GatewayProperties._ConfigureNgrok)
                    ? Constants.HttpsProtocol
                    : session.Get(GatewayProperties._AccessUriScheme);

                string host = session.Get(GatewayProperties._ConfigureNgrok)
                    ? session.Get(GatewayProperties._NgrokHttpDomain)
                    : session.Get(GatewayProperties._AccessUriHost);

                uint port = session.Get(GatewayProperties._ConfigureNgrok)
                    ? 443
                    : session.Get(GatewayProperties._AccessUriPort);

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
                Constants.CertificateMode mode = session.Get(GatewayProperties._CertificateMode);

                if (session.Get(GatewayProperties._ConfigureWebApp) && session.Get(GatewayProperties._GenerateCertificate))
                {
                    command = Constants.NewDGatewayCertificateCommand;
                }
                else if (mode == Constants.CertificateMode.External)
                {
                    if (string.IsNullOrEmpty(session.Get(GatewayProperties._CertificatePassword)))
                    {
                        command = string.Format(
                            Constants.ImportDGatewayCertificateWithPrivateKeyCommandFormat,
                            session.Get(GatewayProperties._CertificateFile),
                            session.Get(GatewayProperties._CertificatePrivateKeyFile));
                    }
                    else
                    {
                        command = string.Format(
                            Constants.ImportDGatewayCertificateWithPasswordCommandFormat,
                            session.Get(GatewayProperties._CertificateFile),
                            session.Get(GatewayProperties._CertificatePassword));
                    }
                }
                else
                {
                    command = string.Format(
                        Constants.ImportDGatewayCertificateFromSystemFormat,
                        session.Get(GatewayProperties._CertificateMode),
                        session.Get(GatewayProperties._CertificateName),
                        session.Get(GatewayProperties._CertificateStore),
                        session.Get(GatewayProperties._CertificateLocation));
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
                    session.Get(GatewayProperties._HttpListenerScheme),
                    session.Get(GatewayProperties._HttpListenerPort));
                string externalUrl = FormatHttpUrl(
                    session.Get(GatewayProperties._AccessUriScheme),
                    session.Get(GatewayProperties._AccessUriPort));

                command = string.Format(Constants.SetDGatewayListenersCommandFormat,
                    internalUrl, externalUrl,
                    session.Get(GatewayProperties._TcpListenerPort),
                    session.Get(GatewayProperties._TcpListenerPort));
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
                command = $"$Ngrok = New-DGatewayNgrokConfig -AuthToken '{session.Get(GatewayProperties._NgrokAuthToken)}'";
                command += $"; $HttpTunnel = New-DGatewayNgrokTunnel -Http -AllowCidrs @('0.0.0.0/0') -Domain '{session.Get(GatewayProperties._NgrokHttpDomain)}'";

                if (session.Get(GatewayProperties._NgrokEnableTcp))
                {
                    command += $"; $TcpTunnel = New-DGatewayNgrokTunnel -Tcp -AllowCidrs @('0.0.0.0/0') -RemoteAddr '{session.Get(GatewayProperties._NgrokRemoteAddress)}'";
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
                if (session.Get(GatewayProperties._ConfigureWebApp) && session.Get(GatewayProperties._GenerateKeyPair))
                {
                    command = Constants.NewDGatewayProvisionerKeyPairCommand;
                }
                else
                {
                    command = Constants.ImportDGatewayProvisionerKeyCommand;

                    if (!string.IsNullOrEmpty(session.Get(GatewayProperties._PublicKeyFile)))
                    {
                        command += $" -PublicKeyFile '{session.Get(GatewayProperties._PublicKeyFile)}'";
                    }

                    if (!string.IsNullOrEmpty(session.Get(GatewayProperties._PrivateKeyFile)))
                    {
                        command += $" -PrivateKeyFile '{session.Get(GatewayProperties._PrivateKeyFile)}'";
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

                switch (session.Get(GatewayProperties._AuthenticationMode))
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
                command = $"Set-DGatewayUser -Username '{session.Get(GatewayProperties._WebUsername)}' -Password '{session.Get(GatewayProperties._WebPassword)}'";
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
            session.Set(GatewayProperties._NetFx45Version, version);

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
                session.Set(GatewayProperties._PowerShellPath, powershellPath);


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
            if (session.Get(GatewayProperties._ConfigureWebApp))
            {
                try
                {
                    string scheme = session.Get(GatewayProperties._ConfigureNgrok)
                        ? Constants.HttpsProtocol
                        : session.Get(GatewayProperties._HttpListenerScheme);

                    string host = session.Get(GatewayProperties._ConfigureNgrok)
                        ? session.Get(GatewayProperties._NgrokHttpDomain)
                        : session.Get(GatewayProperties._AccessUriHost);

                    uint port = session.Get(GatewayProperties._ConfigureNgrok)
                        ? 443
                        : session.Get(GatewayProperties._HttpListenerPort);

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

            session.Set(GatewayProperties._ServiceStart, (int)startMode);
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
                    service.SetStartupType((ServiceStartMode)session.Get(GatewayProperties._ServiceStart));
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
            session.Set(GatewayProperties._InstallId, Guid.NewGuid());
            return ActionResult.Success;
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
                WinAPI.GENERIC_WRITE, WinAPI.FILE_SHARE_WRITE, pSa, WinAPI.CREATE_ALWAYS,
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

            if (session.Get(GatewayProperties._DebugPowerShell))
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
                StringBuilder tempFilePath = new(MAX_PATH);
                uint pathLength = WinAPI.GetFinalPathNameByHandle(hTempFile.DangerousGetHandle(), tempFilePath, MAX_PATH, 0);

                string finalPath = pathLength is < 1 or > MAX_PATH ? "unknown" : tempFilePath.ToString();

                using Record record = new(3)
                {
                    FormatString = "Command execution failure: [1]",
                };

                hTempFile.Close();
                
                record.SetString(1, finalPath);
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
            return $"\"{session.Property(GatewayProperties._PowerShellPath.Id)}\" -ep Bypass -Command \"& Import-Module '{session.Property(GatewayProperties.InstallDir)}PowerShell\\Modules\\DevolutionsGateway'; {command}\"";
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

            if (!Version.TryParse(version, out powerShellVersion))
            {
                return false;
            }

            return true;
        }
    }
}
