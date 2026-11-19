using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace Devolutions.Agent.Desktop.Diagnostics
{
    /// <summary>
    /// Checks the Windows components that hand a dynamic virtual channel to a program.
    /// </summary>
    /// <remarks>
    /// Remote Desktop starts the UmRdpService service, which depends on the rdpdr driver, which depends on RDBSS.
    /// The rdpdr driver provides the \Device\DrDynVc device the Remote Desktop service opens to give a program its
    /// channel handle; without the device every such open fails with error 2. The failure is not reported anywhere else.
    /// </remarks>
    internal static class DeviceRedirectorChecks
    {
        private const string DriverName = "rdpdr";

        private const string DriverDisplayName = "Remote Desktop Device Redirector Driver";

        private const string BufferingName = "RDBSS";

        private const string BufferingDisplayName = "Redirected Buffering Sub System";

        private const string UserModeServiceName = "UmRdpService";

        private const string UserModeServiceDisplayName = "Remote Desktop Services UserMode Port Redirector";

        private const string DeviceName = @"\\.\GLOBALROOT\Device\DrDynVc";

        private const int ErrorFileNotFound = 2;

        private const int ErrorAccessDenied = 5;

        private const int StartTypeDisabled = 4;

        // Generic read and write plus SYNCHRONIZE, as the Remote Desktop service opens the device.
        private const uint DeviceAccess = 0xC0100000;

        private const uint ShareReadWrite = 3;

        private const uint OpenExisting = 3;

        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string fileName,
            uint access,
            uint share,
            IntPtr security,
            uint disposition,
            uint flags,
            IntPtr template);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        internal static ProbeResult[] Run()
        {
            // Remote Desktop starts the device redirector only when it is enabled, so nothing is expected without it.
            if (IsRemoteDesktopEnabled() == false)
            {
                return new[]
                {
                    new ProbeResult(
                        "Remote Desktop connections",
                        "enabled",
                        "disabled; device redirector checks not run",
                        ProbeStatus.Skipped),
                };
            }

            return new[]
            {
                CheckDevice(),
                CheckDriverState(),
                CheckStartType(DriverDisplayName, DriverName),
                CheckStartType(BufferingDisplayName, BufferingName),
                CheckStartType(UserModeServiceDisplayName, UserModeServiceName),
            };
        }

        // The policy setting wins over the local setting. Null when neither can be read, which counts as enabled.
        private static bool? IsRemoteDesktopEnabled()
        {
            int? deny = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections")
                ?? ReadDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");

            return deny == null ? (bool?)null : deny.Value == 0;
        }

        /// <summary>
        /// Whether the results show a configuration that breaks virtual channels opened by programs.
        /// </summary>
        internal static bool IsBroken(IEnumerable<ProbeResult> results)
        {
            foreach (ProbeResult result in results)
            {
                if (result.Status == ProbeStatus.Fail)
                {
                    return true;
                }
            }

            return false;
        }

        // A missing device is the broken state. Access denied for a standard user means the device exists.
        private static ProbeResult CheckDevice()
        {
            const string name = "Remote Desktop redirection device";
            const string expected = "available";

            IntPtr handle = CreateFileW(DeviceName, DeviceAccess, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            int error = handle == InvalidHandle ? Marshal.GetLastWin32Error() : 0;

            if (handle != InvalidHandle)
            {
                CloseHandle(handle);
            }

            if (error == 0)
            {
                return new ProbeResult(name, expected, "available (opened)", ProbeStatus.Pass);
            }

            if (error == ErrorAccessDenied)
            {
                return new ProbeResult(name, expected, "available (error 5)", ProbeStatus.Pass);
            }

            if (error == ErrorFileNotFound)
            {
                return new ProbeResult(
                    name,
                    expected,
                    "not available (error 2)",
                    ProbeStatus.Fail,
                    "The Remote Desktop redirection device is not available.");
            }

            return new ProbeResult(name, expected, $"unexpected error {error}", ProbeStatus.Skipped);
        }

        private static ProbeResult CheckDriverState()
        {
            const string name = DriverDisplayName + " state";
            const string expected = "running";

            try
            {
                using (ServiceController driver = new ServiceController(DriverName))
                {
                    ServiceControllerStatus status = driver.Status;

                    return status == ServiceControllerStatus.Running
                        ? new ProbeResult(name, expected, "running", ProbeStatus.Pass)
                        : new ProbeResult(
                            name,
                            expected,
                            status.ToString().ToLowerInvariant(),
                            ProbeStatus.Fail,
                            "The Remote Desktop Device Redirector Driver is not running.");
                }
            }
            catch (Exception e) when (e is InvalidOperationException || e is System.ComponentModel.Win32Exception)
            {
                return new ProbeResult(name, expected, $"not queried: {e.Message}", ProbeStatus.Skipped);
            }
        }

        private static ProbeResult CheckStartType(string displayName, string serviceName)
        {
            const string expected = "not Disabled";
            string name = displayName + " start type";

            int? start = ReadDword($@"SYSTEM\CurrentControlSet\Services\{serviceName}", "Start");

            if (start == null)
            {
                return new ProbeResult(name, expected, "not read", ProbeStatus.Skipped);
            }

            string actual = $"{DescribeStartType(start.Value)} ({start.Value})";

            return start.Value == StartTypeDisabled
                ? new ProbeResult(name, expected, actual, ProbeStatus.Warning, $"{displayName} is Disabled.")
                : new ProbeResult(name, expected, actual, ProbeStatus.Pass);
        }

        private static int? ReadDword(string subKey, string valueName)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey))
                {
                    return key?.GetValue(valueName) as int?;
                }
            }
            catch (Exception e) when (e is System.Security.SecurityException || e is UnauthorizedAccessException)
            {
                return null;
            }
        }

        private static string DescribeStartType(int start)
        {
            switch (start)
            {
                case 0:
                    return "Boot";
                case 1:
                    return "System";
                case 2:
                    return "Automatic";
                case 3:
                    return "Manual";
                case StartTypeDisabled:
                    return "Disabled";
                default:
                    return "Unknown";
            }
        }
    }
}
