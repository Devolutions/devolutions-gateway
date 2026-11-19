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

        private const string BufferingName = "RDBSS";

        private const string UserModeServiceName = "UmRdpService";

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
            return new[]
            {
                CheckDevice(),
                CheckDriverState(),
                CheckStartType(DriverName, "Device redirector driver (rdpdr) start type"),
                CheckStartType(BufferingName, "Redirected buffering driver (RDBSS) start type"),
                CheckStartType(UserModeServiceName, "UserMode Port Redirector (UmRdpService) start type"),
            };
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
            const string name = @"Device \Device\DrDynVc";
            const string expected = "present (open succeeds or error 5)";

            IntPtr handle = CreateFileW(DeviceName, DeviceAccess, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            int error = handle == InvalidHandle ? Marshal.GetLastWin32Error() : 0;

            if (handle != InvalidHandle)
            {
                CloseHandle(handle);
            }

            if (error == 0)
            {
                return new ProbeResult(name, expected, "present (opened)", ProbeStatus.Pass);
            }

            if (error == ErrorAccessDenied)
            {
                return new ProbeResult(name, expected, "present (error 5)", ProbeStatus.Pass);
            }

            if (error == ErrorFileNotFound)
            {
                return new ProbeResult(
                    name,
                    expected,
                    "missing (error 2)",
                    ProbeStatus.Fail,
                    "The Remote Desktop redirection device (\\Device\\DrDynVc) is missing.");
            }

            return new ProbeResult(name, expected, $"unexpected error {error}", ProbeStatus.Skipped);
        }

        private static ProbeResult CheckDriverState()
        {
            const string name = "Device redirector driver (rdpdr) state";
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
                            "The Remote Desktop device redirector driver (rdpdr) is not running.");
                }
            }
            catch (Exception e) when (e is InvalidOperationException || e is System.ComponentModel.Win32Exception)
            {
                return new ProbeResult(name, expected, $"not queried: {e.Message}", ProbeStatus.Skipped);
            }
        }

        private static ProbeResult CheckStartType(string serviceName, string name)
        {
            const string expected = "not Disabled";

            int? start = ReadStartType(serviceName);

            if (start == null)
            {
                return new ProbeResult(name, expected, "not read", ProbeStatus.Skipped);
            }

            string actual = $"{DescribeStartType(start.Value)} ({start.Value})";

            return start.Value == StartTypeDisabled
                ? new ProbeResult(name, expected, actual, ProbeStatus.Warning, $"{serviceName} is Disabled.")
                : new ProbeResult(name, expected, actual, ProbeStatus.Pass);
        }

        private static int? ReadStartType(string serviceName)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}"))
                {
                    return key?.GetValue("Start") as int?;
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
