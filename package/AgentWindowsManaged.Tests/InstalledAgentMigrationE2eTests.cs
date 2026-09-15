using DevolutionsAgent.Actions;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json.Linq;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace DevolutionsAgent.Installer.Tests;

public sealed class InstalledAgentMigrationE2eTests
{
    private const string CurrentPolicy =
        """{"PolicyFormatVersion":"1.7.3","PolicyType":"PackageBrokerPolicy","Metadata":{"Id":"installer-e2e","Publisher":"Test","Revision":17,"PublishedAt":"2026-01-01T00:00:00Z"},"Enforcement":{"DefaultDecision":"Deny","RulePrecedence":"PriorityThenDeny"},"Rules":[]}""";
    private readonly ITestOutputHelper output;

    public InstalledAgentMigrationE2eTests(ITestOutputHelper output) => this.output = output;

    [Fact]
    public void AgentJobTerminatesChildWhenScopeThrows()
    {
        using Process child = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe"),
            "-NoProfile -NonInteractive -Command Start-Sleep -Seconds 60")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        try
        {
            InvalidOperationException failure = new("simulate a failed Agent assertion");
            void FailWithAssignedChild()
            {
                using AgentJob job = new();
                job.Assign(child);
                throw failure;
            }
            Assert.Same(failure, Assert.Throws<InvalidOperationException>(FailWithAssignedChild));
            Assert.True(child.WaitForExit(10000), "Job disposal left the child running");
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
                Assert.True(child.WaitForExit(10000), "Cleanup did not stop the child");
            }
        }
    }

    [PackageBrokerInstallerTests.SystemFact]
    public void ConvertedTransactionActivatesAndRetainsManagedAuthority()
    {
        Assert.True(WindowsIdentity.GetCurrent().IsSystem);
        string agent = Environment.GetEnvironmentVariable("DEVOLUTIONS_AGENT_MIGRATION_TEST_EXE");
        Assert.False(string.IsNullOrWhiteSpace(agent), "The SYSTEM runner must supply the built Agent executable");
        Assert.True(File.Exists(agent), agent);
        Assert.Equal(Includes.EXECUTABLE_NAME, Path.GetFileName(agent), ignoreCase: true);
        using PackageBrokerPolicyActions.PinnedPath installedAgent =
            PackageBrokerPolicyActions.PinPathWithoutReparse(
                agent, leafIsDirectory: false, allowMissingLeaf: false,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.READ_CONTROL, verifyTrustedAncestors: true);
        Assert.True(
            PackageBrokerPolicyActions.TryVerifyLegacyPolicySourceSecurity(
                File.GetAccessControl(agent), out string agentSecurityDiagnostic),
            agentSecurityDiagnostic);
        string root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            $"dgw-installer-e2e-{Guid.NewGuid():N}");
        PackageBrokerPolicyActions.CreateDirectoryWithSecurity(root, Includes.PROGRAM_DATA_PACKAGE_BROKER_SDDL);
        try
        {
            PackageBrokerPolicyActions.VerifyPackageBrokerSecurity(Directory.GetAccessControl(root));
            string vendor = Path.Combine(root, "Devolutions");
            string legacyDirectory = Path.Combine(vendor, "Agent");
            string managedDirectory = Path.Combine(vendor, "PackageBroker");
            foreach (string directory in new[] { vendor, legacyDirectory, managedDirectory })
            {
                PackageBrokerPolicyActions.CreateDirectoryWithSecurity(
                    directory, Includes.PROGRAM_DATA_PACKAGE_BROKER_SDDL);
            }
            string source = Path.Combine(legacyDirectory, "package-broker-policy.json");
            string destination = Path.Combine(managedDirectory, "package-broker-policy.json");
            string marker = Path.Combine(managedDirectory, ".installer-e2e.migration");
            string authority = Path.Combine(managedDirectory, ".package-broker-managed-authority.v1");
            byte[] original = Encoding.UTF8.GetBytes(CurrentPolicy.Replace(
                "\"PolicyFormatVersion\":",
                "\"$schema\":\"https://devolutions.net/schemas/now-policy.schema.1.0.json\",\"PolicyVersion\":"));
            File.WriteAllBytes(source, original);
            FileSecurity security = new();
            security.SetSecurityDescriptorSddlForm(Includes.PROGRAM_DATA_PACKAGE_BROKER_FILE_SDDL);
            File.SetAccessControl(source, security);

            int conversions = 0;
            void Migrate()
            {
                Assert.Equal(ActionResult.Success, PackageBrokerPolicyActions.MigrateLegacyPolicy(
                    output.WriteLine, source, destination, marker, input =>
                    {
                        Assert.False(File.Exists(destination));
                        Assert.False(File.Exists(authority));
                        Assert.Equal(original, input);
                        byte[] converted = PackageBrokerPolicyActions.ConvertWithInstalledAgent(
                            Path.GetDirectoryName(agent), input);
                        Assert.Equal(CurrentPolicy, Encoding.UTF8.GetString(converted));
                        conversions++;
                        return converted;
                    }));
                Assert.Equal(CurrentPolicy, File.ReadAllText(destination));
                Assert.True(File.Exists(authority));
                Assert.Empty(File.ReadAllBytes(authority));
                AssertPreserved();
                foreach (string path in new[] { destination, authority, marker, marker + ".original" })
                {
                    PackageBrokerPolicyActions.VerifyPackageBrokerSecurity(File.GetAccessControl(path));
                }
            }
            void AssertPreserved()
            {
                Assert.Equal(original, File.ReadAllBytes(source));
                Assert.Equal(original, File.ReadAllBytes(marker + ".original"));
                Assert.True(File.Exists(marker));
            }

            Migrate();
            Assert.Equal(ActionResult.Success, PackageBrokerPolicyActions.RollbackLegacyPolicy(
                output.WriteLine, source, destination, marker));
            Assert.False(File.Exists(destination));
            Assert.False(File.Exists(authority));
            AssertPreserved();
            Migrate();
            Assert.Equal(2, conversions);
            PackageBrokerPolicyActions.CommitLegacyPolicy(output.WriteLine, source, destination, marker);
            AssertPreserved();

            using AgentProcess running = new(agent, root, output);
            running.Start();
            JToken active = AssertActive(running, destination);
            running.Stop();
            running.Start();
            Assert.True(JToken.DeepEquals(active, AssertActive(running, destination)));
            AssertPreserved();
            running.Stop();
            File.Delete(destination);
            running.Start();
            JObject management = running.Get("/v1/policy/management", 200)["Management"] as JObject;
            Assert.NotNull(management);
            Assert.Equal("DefaultPath", (string)management["Source"]);
            Assert.Equal("Missing", (string)management["State"]);
            Assert.Equal("active policy is unavailable", (string)running.Get("/v1/policy", 404)["Message"]);
            Assert.True(File.Exists(authority));
            AssertPreserved();
        }
        finally
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    Directory.Delete(root, recursive: true);
                    break;
                }
                catch (IOException) when (attempt < 19)
                {
                    Thread.Sleep(250);
                }
            }
        }
    }

    private static JToken AssertActive(AgentProcess agent, string destination)
    {
        JObject response = agent.Get("/v1/policy", 200);
        JToken policy = response["Policy"];
        Assert.NotNull(policy);
        Assert.Equal("1.7.3", (string)policy["PolicyFormatVersion"]);
        Assert.Equal("PackageBrokerPolicy", (string)policy["PolicyType"]);
        Assert.Null(policy["PolicyVersion"]);
        Assert.Null(policy["$schema"]);
        Assert.Equal("installer-e2e", (string)policy["Metadata"]["Id"]);
        Assert.Equal("Test", (string)policy["Metadata"]["Publisher"]);
        Assert.Equal(17, (int)policy["Metadata"]["Revision"]);
        Assert.Equal(
            JObject.Parse(CurrentPolicy)["Metadata"]["PublishedAt"],
            policy["Metadata"]["PublishedAt"]);
        Assert.True(JToken.DeepEquals(JObject.Parse(CurrentPolicy)["Enforcement"], policy["Enforcement"]));
        Assert.True(JToken.DeepEquals(new JArray(), policy["Rules"]));
        Assert.Equal(CurrentPolicy, File.ReadAllText(destination));
        JObject management = agent.Get("/v1/policy/management", 200)["Management"] as JObject;
        Assert.NotNull(management);
        Assert.Equal("DefaultPath", (string)management["Source"]);
        Assert.Equal("Active", (string)management["State"]);
        return policy;
    }

    private sealed class AgentProcess : IDisposable
    {
        private readonly string executable;
        private readonly string root;
        private readonly ITestOutputHelper output;
        private readonly string pipeName = $"Devolutions.Now.PackageBroker.installer-e2e.{Guid.NewGuid():N}";
        private readonly AgentJob job;
        private Process process;
        private Task<string> stdout;
        private Task<string> stderr;

        internal AgentProcess(string executable, string root, ITestOutputHelper output)
        {
            this.executable = executable;
            this.root = root;
            this.output = output;
            JObject config = new()
            {
                ["LogFile"] = Path.Combine(root, "agent-installer-e2e"),
                ["PackageBroker"] = new JObject
                {
                    ["Enabled"] = true,
                    ["PipeName"] = @"\\.\pipe\" + pipeName,
                },
                ["__debug__"] = new JObject { ["skip_broker_signature_validation"] = true },
            };
            File.WriteAllText(Path.Combine(root, "agent.json"), config.ToString());
            job = new AgentJob();
        }

        internal void Start()
        {
            Assert.Null(process);
            stdout = null;
            stderr = null;
            ProcessStartInfo start = new(executable, "run")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.EnvironmentVariables["DAGENT_CONFIG_PATH"] = root;
            start.EnvironmentVariables["ProgramData"] = root;
            process = Process.Start(start);
            job.Assign(process);
            stdout = process.StandardOutput.ReadToEndAsync();
            stderr = process.StandardError.ReadToEndAsync();
            Stopwatch timer = Stopwatch.StartNew();
            while (true)
            {
                Assert.False(process.HasExited, "Agent exited before its broker became ready");
                try
                {
                    Get("/v1/health", 200);
                    return;
                }
                catch (TimeoutException) when (timer.Elapsed < TimeSpan.FromSeconds(20))
                {
                    Thread.Sleep(50);
                }
                catch (IOException) when (timer.Elapsed < TimeSpan.FromSeconds(20))
                {
                    Thread.Sleep(50);
                }
            }
        }

        internal JObject Get(string path, int expectedStatus)
        {
            using NamedPipeClientStream pipe = new(
                ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            pipe.Connect(1000);
            Task<string> request = Exchange(pipe, path);
            if (Task.WhenAny(request, Task.Delay(TimeSpan.FromSeconds(10))).GetAwaiter().GetResult() != request)
            {
                throw new TimeoutException($"timed out reading {path}");
            }
            string response = request.GetAwaiter().GetResult();
            int headerEnd = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            Assert.True(headerEnd > 0, response);
            Assert.Equal(expectedStatus.ToString(), response.Split(' ')[1]);
            return JObject.Parse(response.Substring(headerEnd + 4));
        }

        private static async Task<string> Exchange(NamedPipeClientStream pipe, string path)
        {
            byte[] request = Encoding.ASCII.GetBytes(
                $"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            await pipe.WriteAsync(request, 0, request.Length).ConfigureAwait(false);
            await pipe.FlushAsync().ConfigureAwait(false);
            using MemoryStream response = new();
            await pipe.CopyToAsync(response).ConfigureAwait(false);
            return Encoding.UTF8.GetString(response.ToArray());
        }

        internal void Stop()
        {
            if (process == null)
            {
                return;
            }
            try
            {
                if (!process.HasExited)
                {
                    try
                    {
                        process.Kill();
                    }
                    catch (InvalidOperationException) when (process.HasExited)
                    {
                    }
                    catch (Win32Exception) when (process.WaitForExit(10000))
                    {
                    }
                }
                Assert.True(process.WaitForExit(10000), "Agent did not stop");
                if (stdout != null)
                {
                    output.WriteLine(stdout.GetAwaiter().GetResult());
                    output.WriteLine(stderr.GetAwaiter().GetResult());
                }
                foreach (string log in Directory.GetFiles(root, "agent-installer-e2e*"))
                {
                    output.WriteLine(File.ReadAllText(log));
                }
            }
            finally
            {
                if (process.HasExited)
                {
                    process.Dispose();
                    process = null;
                }
            }
        }

        public void Dispose()
        {
            job.Dispose();
            Stop();
        }
    }

    private sealed class AgentJob : IDisposable
    {
        private const uint JobObjectLimitKillOnJobClose = 0x2000;
        private const int JobObjectExtendedLimitInformation = 9;
        private readonly SafeFileHandle handle;

        internal AgentJob()
        {
            handle = CreateJobObjectW(IntPtr.Zero, null);
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            ExtendedLimitInformation limits = new()
            {
                BasicLimitInformation = new BasicLimitInformation { LimitFlags = JobObjectLimitKillOnJobClose },
            };
            if (!SetInformationJobObject(
                handle, JobObjectExtendedLimitInformation, ref limits, Marshal.SizeOf<ExtendedLimitInformation>()))
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
        }

        internal void Assign(Process process)
        {
            if (!AssignProcessToJobObject(handle, process.Handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public void Dispose() => handle.Dispose();

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation
        {
            internal BasicLimitInformation BasicLimitInformation;
            internal IoCounters IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            SafeFileHandle job, int informationClass, ref ExtendedLimitInformation information, int length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    }
}
