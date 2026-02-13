using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Threading;
using WixSharp;
using File = System.IO.File;

namespace DevolutionsAgent.Actions
{
    public class CustomActions
    {
        private const string EXPLORER_COMMAND_VERB = "RunElevated";

        private static readonly string[] ConfigFiles = new[]
        {
            "agent.json",
        };

        private static readonly string[] explorerCommandExtensions = [".exe", ".msi", ".lnk", ".ps1", ".bat"];

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
                string zipFile =
                    $"{Path.Combine(Path.GetTempPath(), session.Get(AgentProperties.installId).ToString())}.zip";
                using ZipArchive archive = ZipFile.Open(zipFile, ZipArchiveMode.Create);

                WinAPI.MoveFileEx(zipFile, null, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);

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
            string zipFile =
                $"{Path.Combine(Path.GetTempPath(), session.Get(AgentProperties.installId).ToString())}.zip";

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

            try
            {
                DirectoryInfo di = Directory.CreateDirectory(rootPath);
                session.Log($"created directory at {di.FullName} or already exists");
            }
            catch (Exception e)
            {
                session.Log($"failed to evaluate or create path {rootPath}: {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult GetInstallDirFromRegistry(Session session)
        {
            try
            {
                using RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine,
                    RegistryView.Registry64);
                using RegistryKey agentKey =
                    localKey.OpenSubKey($@"Software\{Includes.VENDOR_NAME}\{Includes.SHORT_NAME}");
                string installDirValue = (string) agentKey.GetValue("InstallDir");

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

        [CustomAction]
        public static ActionResult LaunchDesktopApp(Session session)
        {
            try
            {
                string installDir = session.Property(AgentProperties.InstallDir);

                if (string.IsNullOrEmpty(installDir))
                {
                    session.Log("skipping launch of desktop application due to empty install dir");
                    return ActionResult.Success;
                }

                string path = Path.Combine(installDir, Includes.DESKTOP_DIRECTORY_NAME, Includes.DESKTOP_EXECUTABLE_NAME);

                if (!File.Exists(path))
                {
                    session.Log($"skipping launch of desktop application due to missing executable at {path}");
                    return ActionResult.Success;
                }

                ProcessStartInfo startInfo = new ProcessStartInfo(path)
                {
                    WorkingDirectory = Path.Combine(installDir, Includes.DESKTOP_DIRECTORY_NAME),
                    UseShellExecute = true,
                };

                Process.Start(startInfo);

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"unexpected error launching desktop application {e}");
                return ActionResult.Failure;
            }

        }

        static ActionResult ToggleAgentFeature(Session session, string feature, bool enable)
        {
            string path = Path.Combine(ProgramDataDirectory, "agent.json");

            try
            {
                Dictionary<string, object> config = [];

                try
                {
                    using StreamReader reader = new StreamReader(path);
                    config = JsonConvert.DeserializeObject<Dictionary<string, object>>(reader.ReadToEnd());
                }
                catch (Exception)
                {
                    // ignored. Previous config is either invalid or non-existent.
                }

                config[feature] = new Dictionary<string, bool> {{"Enabled", enable}};

                using StreamWriter writer = new StreamWriter(path);
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
        public static ActionResult ConfigureFeatures(Session session)
        {
            foreach (Feature feature in (Feature[]) [Features.SESSION_FEATURE, Features.PEDM_FEATURE, Features.AGENT_UPDATER_FEATURE])
            {
                bool enable = session.IsFeatureEnabled(feature.Id);
                string jsonId = feature.Id.Substring(Features.FEATURE_ID_PREFIX.Length);
                ToggleAgentFeature(session, jsonId, enable);
            }

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult RegisterExplorerCommand(Session session)
        {
            try
            {
                string installDir = session.Property(AgentProperties.InstallDir);
                string dllPath = Path.Combine(installDir, "ShellExt", Includes.SHELL_EXT_BINARY_NAME);

                if (!File.Exists(dllPath))
                {
                    session.Log($"can't register dll that does not exist on disk {dllPath}");
                    return ActionResult.Failure;
                }

                string destinationDllPath = Path.Combine(installDir, Includes.SHELL_EXT_BINARY_NAME);
                File.Copy(dllPath, destinationDllPath, true);
                
                string clsidPath = $"CLSID\\{Includes.SHELL_EXT_CSLID:B}";

                using RegistryKey clsidKey = Registry.ClassesRoot.CreateSubKey(clsidPath);

                if (clsidKey is null)
                {
                    session.Log("couldn't open or create key");
                    return ActionResult.Failure;
                }

                clsidKey.SetValue("", "PedmShellExt", RegistryValueKind.String);

                using RegistryKey inprocKey = Registry.ClassesRoot.CreateSubKey($"{clsidPath}\\InprocServer32");

                if (inprocKey is null)
                {
                    session.Log("couldn't open or create key");
                    return ActionResult.Failure;
                }

                inprocKey.SetValue("", destinationDllPath, RegistryValueKind.String);
                inprocKey.SetValue("ThreadingModel", "Apartment", RegistryValueKind.String);

                const string explorerCommandDefaultText = "Run Elevated";

                foreach (string extension in explorerCommandExtensions)
                {
                    object fileClass = Registry.GetValue($"{Registry.ClassesRoot.Name}\\{extension}", "", extension);

                    if (fileClass is null)
                    {
                        session.Log($"couldn't find file class for extension {extension}");
                        continue;
                    }

                    using RegistryKey commandPath =
                        Registry.ClassesRoot.CreateSubKey($"{fileClass}\\shell\\{EXPLORER_COMMAND_VERB}");

                    if (commandPath is null)
                    {
                        session.Log("couldn't open or create key");
                        continue;
                    }

                    commandPath.SetValue("", explorerCommandDefaultText, RegistryValueKind.String);
                    commandPath.SetValue("ExplorerCommandHandler", $"{Includes.SHELL_EXT_CSLID:B}",
                        RegistryValueKind.String);
                    commandPath.SetValue("MUIVerb", $"{destinationDllPath},-150", RegistryValueKind.String);
                }

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"unexpected error registering explorer command {e}");
                return ActionResult.Failure;
            }
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
        public static ActionResult ShutdownDesktopApp(Session session)
        {
            string processName = Path.GetFileNameWithoutExtension(Includes.DESKTOP_EXECUTABLE_NAME);

            try
            {
                foreach (Process process in Process.GetProcessesByName(processName))
                {
                    session.Log($"found instance of {processName} with PID {process.Id} in session {process.SessionId}");

                    if (!process.CloseMainWindow())
                    {
                        const string mutexId = "BF3262DE-F439-455F-B67F-9D32D9FD5E58";
                        using EventWaitHandle quitEvent = new EventWaitHandle(false, EventResetMode.ManualReset, $"{mutexId}_{process.Id}");
                        quitEvent.Set();
                    }
                    
                    process.WaitForExit((int)TimeSpan.FromSeconds(1).TotalMilliseconds);

                    if (process.HasExited)
                    {
                        session.Log("process ended gracefully");
                        continue;
                    }

                    session.Log("terminating process forcefully");

                    process.Kill();
                }
            }
            catch (Exception e)
            {
                session.Log($"unexpected error: {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
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

        public static void SetFileSecurity(Session session, string path, string sddl)
        {
            const uint sdRevision = 1;
            IntPtr pSd = new IntPtr();
            UIntPtr pSzSd = new UIntPtr();

            try
            {
                if (!WinAPI.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, sdRevision, out pSd, out pSzSd))
                {
                    session.Log(
                        $"ConvertStringSecurityDescriptorToSecurityDescriptorW failed (error: {Marshal.GetLastWin32Error()})");
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
                using RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine,
                    RegistryView.Registry64);
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

        [CustomAction]
        public static ActionResult UnregisterExplorerCommand(Session session)
        {
            try
            {
                string installDir = session.Property(AgentProperties.InstallDir);
                string dllPath = Path.Combine(installDir, Includes.SHELL_EXT_BINARY_NAME);

                if (!ScheduleFileDeletion(session, dllPath, true))
                {
                    session.Log($"failed to schedule file {dllPath} for deletion");
                }

                Registry.ClassesRoot.DeleteSubKeyTree($"CLSID\\{Includes.SHELL_EXT_CSLID:B}", false);

                foreach (string extension in explorerCommandExtensions)
                {
                    object fileClass = Registry.GetValue($"{Registry.ClassesRoot.Name}\\{extension}", "", extension);

                    if (fileClass is null)
                    {
                        session.Log($"couldn't find file class for extension {extension}");
                        continue;
                    }

                    Registry.ClassesRoot.DeleteSubKeyTree($"{fileClass}\\shell\\{EXPLORER_COMMAND_VERB}", false);
                }
            }
            catch (Exception e)
            {
                session.Log($"unexpected error unregistering explorer command {e}");
                return ActionResult.Failure;
            }

            return ActionResult.Success;
        }

        private static bool ScheduleFileDeletion(Session session, string filePath, bool moveToTempDirectory)
        {
            bool moveResult = false;

            try
            {
                if (!File.Exists(filePath))
                {
                    return moveResult;
                }

                if (moveToTempDirectory)
                {
                    string tempPath = Path.GetTempFileName();

                    // Move the file to the temporary directory. It can be moved even if loaded into memory and locked.
                    if (!WinAPI.MoveFileEx(filePath, tempPath, WinAPI.MOVEFILE_REPLACE_EXISTING))
                    {
                        return moveResult;
                    }

                    moveResult = WinAPI.MoveFileEx(tempPath, null, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);
                }
                else
                {
                    moveResult = WinAPI.MoveFileEx(filePath, null, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);
                }

                return moveResult;
            }
            catch (Exception e)
            {
                session.Log($"failed to schedule file deletion: {e}");
                return false;
            }
        }
    }
}
