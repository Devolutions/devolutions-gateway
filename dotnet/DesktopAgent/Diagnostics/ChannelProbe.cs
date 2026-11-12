using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Devolutions.Agent.Desktop.Diagnostics
{
    internal enum ProbeStatus
    {
        Pass,
        Fail,
        Skipped,
    }

    internal sealed class ProbeResult
    {
        public ProbeResult(string channel, string expected, string actual, ProbeStatus status)
        {
            this.Channel = channel;
            this.Expected = expected;
            this.Actual = actual;
            this.Status = status;
        }

        public string Channel { get; }

        public string Expected { get; }

        public string Actual { get; }

        public ProbeStatus Status { get; }
    }

    /// <summary>
    /// Opens dynamic virtual channels from the current session with the same Windows call the session host uses,
    /// and compares each outcome with the one a healthy remote session produces.
    /// </summary>
    internal static class ChannelProbe
    {
        private const string NowChannel = "Devolutions::Now::Agent";

        // Registered by the Microsoft RDP client itself, so it opens whenever dynamic channels work.
        private const string BuiltInChannel = "ECHO";

        // No client registers this name, so the client refuses it. The Microsoft client reports the refusal as error 31;
        // other clients report their own status.
        private const string UnregisteredChannel = "Devolutions::Probe::Unregistered";

        private const string SessionHostProcess = "DevolutionsSession";

        private const int ErrorGenFailure = 31;

        private const uint WtsCurrentSession = 0xFFFFFFFF;

        private const uint WtsChannelOptionDynamic = 1;

        private const int SmRemoteSession = 0x1000;

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr WTSVirtualChannelOpenEx(uint sessionId, string virtualName, uint flags);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSVirtualChannelClose(IntPtr channel);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int index);

        internal static string Run()
        {
            int sessionId = Process.GetCurrentProcess().SessionId;
            bool remote = GetSystemMetrics(SmRemoteSession) != 0;

            StringBuilder report = new StringBuilder();
            report.AppendLine("Virtual channel diagnostics");
            report.AppendLine($"Time:     {DateTime.Now:yyyy-MM-dd HH:mm:ss zzz}");
            report.AppendLine($"Session:  {sessionId} ({(remote ? "RDP" : "console")})");
            report.AppendLine($"User:     {WindowsIdentity.GetCurrent().Name}");
            report.AppendLine($"Elevated: {IsElevated()}");
            report.AppendLine($"OS:       {Environment.OSVersion.Version}");
            report.AppendLine();

            if (!remote)
            {
                report.AppendLine("Not run: virtual channels are only available in a remote desktop session.");

                return report.ToString();
            }

            ProbeResult[] results =
            {
                Probe(BuiltInChannel, expectedError: 0),
                ProbeNow(sessionId),
                Probe(UnregisteredChannel, expectedError: ErrorGenFailure, anyFailure: true),
            };

            foreach (ProbeResult result in results)
            {
                report.AppendLine(result.Channel);
                report.AppendLine($"  Expected: {result.Expected}");
                report.AppendLine($"  Result:   {result.Actual}");
                report.AppendLine($"  Status:   {result.Status.ToString().ToUpperInvariant()}");
                report.AppendLine();
            }

            int passed = results.Count(r => r.Status == ProbeStatus.Pass);
            int run = results.Count(r => r.Status != ProbeStatus.Skipped);
            report.AppendLine($"{passed} of {run} checks passed.");

            return report.ToString();
        }

        private static ProbeResult ProbeNow(int sessionId)
        {
            // UNTESTED: opening the Now channel while the session host is connected offers RDM a second channel, which
            // replaces the live one; this check is the only guard, so when changing it, make sure the channel is never
            // opened while a session host runs in this session.
            if (IsSessionHostRunning(sessionId))
            {
                return new ProbeResult(
                    NowChannel,
                    DescribeExpected(0),
                    "not opened: Devolutions Session is running in this session and holds the channel",
                    ProbeStatus.Skipped);
            }

            return Probe(NowChannel, expectedError: 0);
        }

        private static ProbeResult Probe(string channel, int expectedError, bool anyFailure = false)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            IntPtr handle = WTSVirtualChannelOpenEx(WtsCurrentSession, channel, WtsChannelOptionDynamic);
            int error = handle == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
            stopwatch.Stop();

            if (handle != IntPtr.Zero)
            {
                WTSVirtualChannelClose(handle);
            }

            string actual = error == 0
                ? $"opened ({stopwatch.ElapsedMilliseconds} ms)"
                : $"{DescribeError(error)} ({stopwatch.ElapsedMilliseconds} ms)";

            string expected = anyFailure
                ? $"refused ({DescribeError(expectedError)} with the Microsoft client)"
                : DescribeExpected(expectedError);

            bool pass = anyFailure ? error != 0 : error == expectedError;

            return new ProbeResult(channel, expected, actual, pass ? ProbeStatus.Pass : ProbeStatus.Fail);
        }

        private static string DescribeExpected(int expectedError)
        {
            return expectedError == 0 ? "opened" : DescribeError(expectedError);
        }

        private static string DescribeError(int error)
        {
            return $"error {error} ({new Win32Exception(error).Message})";
        }

        private static bool IsSessionHostRunning(int sessionId)
        {
            Process[] processes = Process.GetProcessesByName(SessionHostProcess);

            try
            {
                return processes.Any(process => IsInSession(process, sessionId));
            }
            finally
            {
                foreach (Process process in processes)
                {
                    process.Dispose();
                }
            }
        }

        private static bool IsInSession(Process process, int sessionId)
        {
            try
            {
                return process.SessionId == sessionId;
            }
            catch (InvalidOperationException)
            {
                // The process exited between the lookup and the query.
                return false;
            }
        }

        private static bool IsElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
