using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Windows.Management.Deployment;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using WixSharp;
using File = System.IO.File;

namespace DevolutionsAgent.Actions
{
    public class CustomActions
    {
        private static readonly string[] ConfigFiles = new[] {
            "agent.json",
        };

        private const int MAX_PATH = 260; // Defined in windows.h

        private static string ProgramDataDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Devolutions", "Agent");

        [CustomAction]
        public static ActionResult CheckInstalledNetFx45Version(Session session)
        {
            uint version = session.Get(AgentProperties.netFx45Version);

            if (version < 528040) // 4.8
            {
                session.Log($"netfx45 version: {version} is too old");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult CleanAgentConfig(Session session)
        {
            if (!ConfigFiles.Any(x => File.Exists(Path.Combine(ProgramDataDirectory, x))))
            {
                return ActionResult.Success;
            }

            try
            {
                string zipFile = $"{Path.Combine(Path.GetTempPath(), session.Get(AgentProperties.installId).ToString())}.zip";
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
        public static ActionResult CleanAgentConfigRollback(Session session)
        {
            string zipFile = $"{Path.Combine(Path.GetTempPath(), session.Get(AgentProperties.installId).ToString())}.zip";

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
        public static ActionResult CreateProgramDataDirectory(Session session)
        {
            string path = ProgramDataDirectory;

            try
            {
                DirectoryInfo di = Directory.CreateDirectory(path);
                session.Log($"created directory at {di.FullName} or already exists");
            }
            catch (Exception e)
            {
                session.Log($"failed to evaluate or create path {path}: {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult CreateProgramDataPedmDirectories(Session session)
        {
            string rootPath = Path.Combine(ProgramDataDirectory, "pedm");

            foreach (string directory in new[]
                     {
                         "logs", 
                         Path.Combine("policy", "profiles"), 
                         Path.Combine("policy", "rules")
                     })
            {
                string path = Path.Combine(rootPath, directory);

                try
                {
                    DirectoryInfo di = Directory.CreateDirectory(path);
                    session.Log($"created directory at {di.FullName} or already exists");
                }
                catch (Exception e)
                {
                    session.Log($"failed to evaluate or create path {path}: {e}");
                    return ActionResult.Failure;
                }
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult GetInstallDirFromRegistry(Session session)
        {
            try
            {
                using RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64);
                using RegistryKey agentKey = localKey.OpenSubKey($@"Software\{Includes.VENDOR_NAME}\{Includes.SHORT_NAME}");
                string installDirValue = (string)agentKey.GetValue("InstallDir");

                if (string.IsNullOrEmpty(installDirValue))
                {
                    throw new Exception("failed to read installdir path from registry: path is null or empty");
                }

                session.Log($"read installdir path from registry: {installDirValue}");
                session[AgentProperties.InstallDir] = installDirValue;

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
            session.Set(AgentProperties.netFx45Version, version);

            return ActionResult.Success;
        }

        static ActionResult EnableAgentFeature(Session session, string feature)
        {
            string path = Path.Combine(ProgramDataDirectory, "agent.json");

            try
            {
                Dictionary<string, object> config = [];
                try
                {
                    using var reader = new StreamReader(path);
                    config = JsonConvert.DeserializeObject<Dictionary<string, object>>(reader.ReadToEnd());
                }
                catch (Exception)
                {
                    // ignored. Previous config is either invalid or non existent.
                }

                config[feature] = new Dictionary<string, bool> { { "Enabled", true } };

                using var writer = new StreamWriter(path);
                writer.Write(JsonConvert.SerializeObject(config));

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to install {feature}: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult InstallPedm(Session session)
        {
            return EnableAgentFeature(session, "Pedm");
        }

        [CustomAction]
        public static ActionResult InstallSession(Session session)
        {
            return EnableAgentFeature(session, "Session");
        }

        [CustomAction]
        public static ActionResult RestartAgent(Session session)
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
        public static ActionResult SetInstallId(Session session)
        {
            session.Set(AgentProperties.installId, Guid.NewGuid());
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult SetProgramDataDirectoryPermissions(Session session)
        {
            try
            {
                SetFileSecurity(session, ProgramDataDirectory, Includes.PROGRAM_DATA_SDDL);
                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to set permissions: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult SetProgramDataPedmDirectoryPermissions(Session session)
        {
            try
            {
                SetFileSecurity(session, Path.Combine(ProgramDataDirectory, "pedm"), Includes.PROGRAM_DATA_PEDM_SDDL);
                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to set permissions: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult StartAgentIfNeeded(Session session)
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

            if (session.Get(AgentProperties.debugPowerShell))
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

                        using FileStream fileStream = new(tempFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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

        [CustomAction]
        public static ActionResult InstallMsix(Session session)
        {
            try
            {
                string packageName = "DevolutionsAgent";
                string installPath = session.Property("INSTALLDIR");
                string packageFileName = "DevolutionsPedmShellExt.msix";
                string packagePath = System.IO.Path.Combine(installPath, packageFileName);

                session.Log($"Installing MSIX package from path: {packagePath}");
                session.Log($"with external location: {installPath}");

                InstallMsixPackage(packagePath, installPath);
                return ActionResult.Success;
            }
            catch (Exception ex)
            {
                session.Log("ERROR: " + ex.Message);
                session.Log("Stack Trace: " + ex.StackTrace);
                if (ex.InnerException != null)
                {
                    session.Log("Inner Exception: " + ex.InnerException.Message);
                    session.Log("Inner Exception Stack Trace: " + ex.InnerException.StackTrace);
                }
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult UninstallMsix(Session session)
        {
            try
            {
                string packageFamilyName = "DevolutionsAgent_tr5fa5yv8zr8w";
                UninstallMsixPackage(packageFamilyName);
                return ActionResult.Success;
            }
            catch (Exception ex)
            {
                session.Log("ERROR: " + ex.Message);
                session.Log("Stack Trace: " + ex.StackTrace);
                if (ex.InnerException != null)
                {
                    session.Log("Inner Exception: " + ex.InnerException.Message);
                    session.Log("Inner Exception Stack Trace: " + ex.InnerException.StackTrace);
                }
                return ActionResult.Failure;
            }
        }

        private static void InstallMsixPackage(string packagePath, string externalLocation)
        {
            var packageManager = new PackageManager();

            if (!string.IsNullOrEmpty(externalLocation))
            {
                var options = new AddPackageOptions();
                options.ExternalLocationUri = new Uri(externalLocation);
                var deploymentOperation = packageManager.AddPackageByUriAsync(
                    new Uri(packagePath), options
                );
                deploymentOperation.AsTask().Wait();
            }
            else
            {
                var deploymentOperation = packageManager.AddPackageAsync(
                    new Uri(packagePath), null, DeploymentOptions.None
                );
                deploymentOperation.AsTask().Wait();
            }
        }

        public static void UninstallMsixPackage(string packageFamilyName)
        {
            var packageManager = new PackageManager();

            var packages = packageManager.FindPackages(packageFamilyName);

            if (packages != null && packages.Any())
            {
                foreach (var package in packages)
                {
                    var deploymentOperation = packageManager.RemovePackageAsync(package.Id.FullName, RemovalOptions.RemoveForAllUsers);
                    deploymentOperation.AsTask().Wait();
                }
            }
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
    }
}
