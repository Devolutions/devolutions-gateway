using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
using System.Threading.Tasks;
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
                // Only start from an empty object when agent.json is genuinely absent. If the file
                // exists but can't be read or parsed (permission, sharing, corruption), let the
                // exception reach the outer handler and fail the action instead of silently
                // overwriting it — a write of a feature-only object here would drop every other
                // agent setting (tunnel certs, PSU config, etc.).
                JObject config;
                if (File.Exists(path))
                {
                    using StreamReader reader = new StreamReader(path);
                    config = JObject.Parse(reader.ReadToEnd());
                }
                else
                {
                    config = new JObject();
                }

                if (config[feature] is not JObject featureConfig)
                {
                    featureConfig = new JObject();
                    config[feature] = featureConfig;
                }

                featureConfig["Enabled"] = enable;

                // WARNING: Always pass an explicit JsonConverter[] to JToken/JObject.ToString(Formatting, ...).
                // Newtonsoft.Json keeps the same AssemblyVersion (13.0.0.0) across every 13.x patch release, so the
                // CLR loads whatever 13.x copy is in the GAC in preference to the one bundled in the SFXCA payload,
                // regardless of what this project references. The single-argument ToString(Formatting) overload was
                // only added in 13.0.4; binding to it crashes with MissingMethodException when an older 13.x is in
                // the GAC (common: RDM, PowerShell 7, Dell Command, etc.), which rolls back the whole install. The
                // two-argument ToString(Formatting, params JsonConverter[]) overload exists in every 13.x, so forcing
                // it keeps us safe no matter which 13.x wins assembly resolution. See Newtonsoft.Json issue #3084.
                // Write atomically so a failure mid-write can't truncate agent.json and leave the
                // ConfigurePsuAgent rollback unable to re-parse it.
                WriteFileAtomic(path, config.ToString(Formatting.None, Array.Empty<JsonConverter>()));

                return ActionResult.Success;
            }
            catch (Exception e)
            {
                session.Log($"failed to install {feature}: {e}");
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult SetFeaturesToConfigure(Session session)
        {
            // session.Features is only accessible from immediate custom actions (DTF restriction).
            // Encode the requested feature states into a session property so the deferred
            // ConfigureFeatures action can read them via CustomActionData.
            (string featureId, string jsonId)[] features =
            [
                (Features.SESSION_FEATURE.Id, Features.SESSION_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length)),
                (Features.AGENT_UPDATER_FEATURE.Id, Features.AGENT_UPDATER_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length)),
                (Features.PSU_FEATURE.Id, Features.PSU_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length)),
                (Features.PEDM_FEATURE.Id, Features.PEDM_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length)),
            ];

            List<string> toEnable = [];

            foreach ((string featureId, string jsonId) in features)
            {
                if (session.Features[featureId].RequestState == InstallState.Local)
                {
                    toEnable.Add(jsonId);
                }
            }

            session[AgentProperties.featuresToConfigure.Id] = string.Join(",", toEnable);

            return ActionResult.Success;
        }

        /// <summary>
        /// Best-effort read of the freshly-written agent.json Tunnel section, collecting the
        /// non-empty <c>ClientCertPath</c> / <c>ClientKeyPath</c> / <c>GatewayCaCertPath</c> values
        /// into a list. Never throws: a missing/locked/partial agent.json or missing Tunnel section
        /// just yields whatever (possibly nothing) was found. Shared by EnrollAgentTunnel's marker
        /// block and its timeout-path inline cleanup.
        /// </summary>
        private static List<string> ReadTunnelCertPaths(string agentJsonPath)
        {
            List<string> paths = new();
            try
            {
                if (File.Exists(agentJsonPath))
                {
                    JObject root = JObject.Parse(File.ReadAllText(agentJsonPath));
                    if (root["Tunnel"] is JObject tunnel)
                    {
                        foreach (string field in new[] { "ClientCertPath", "ClientKeyPath", "GatewayCaCertPath" })
                        {
                            string value = tunnel[field]?.Value<string>();
                            if (!string.IsNullOrEmpty(value))
                            {
                                paths.Add(value);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Best-effort: return whatever was collected so far. agent.json may be locked,
                // absent, or partially written (e.g. on the timeout path).
            }

            return paths;
        }

        [CustomAction]
        public static ActionResult EnrollAgentTunnel(Session session)
        {
            string enrollmentString = session.Property(AgentProperties.AgentTunnelEnrollmentString)?.Trim() ?? string.Empty;
            string subnetsArg = session.Property(AgentProperties.AgentTunnelAdvertiseSubnets)?.Trim() ?? string.Empty;
            string domainsArg = session.Property(AgentProperties.AgentTunnelAdvertiseDomains)?.Trim() ?? string.Empty;
            ActionResult Fail(string msg)
            {
                session.Log(msg);
                using Record record = new(0) { FormatString = msg };
                session.Message(InstallMessage.Error, record);
                return ActionResult.Failure;
            }

            if (enrollmentString.Length == 0)
            {
                return Fail("An enrollment string is required. Paste the enrollment string provided by your gateway operator, or deselect the Agent Tunnel feature.");
            }

            try
            {
                // Hand the enrollment string through verbatim. The agent's
                // `up --enrollment-string` parses the gateway URL and agent name out of it.
                // Advertise domains aren't a CLI flag — agent.json carries them — so we patch
                // that after enrollment succeeds.
                string installDir = session.Property(AgentProperties.InstallDir);
                string exePath = Path.Combine(installDir, Includes.EXECUTABLE_NAME);

                // The rollback CA (RollbackEnrollAgentTunnel) is marker-driven: it only touches
                // disk if this forward action got far enough to write the marker. The marker is
                // keyed by installId (bubbled through CustomActionData) and carries enough state to
                // both clean up what `up` wrote and restore anything it overwrote.
                string installId = session.Get(AgentProperties.installId).ToString();
                string markerPath = Path.Combine(Path.GetTempPath(), $"{installId}-tunnel-rollback.json");

                // Snapshot the pre-enrollment state BEFORE `up` runs so rollback can restore it.
                // Best-effort: any failure here just leaves the snapshot null, which means rollback
                // will delete (rather than restore) — the safe direction is no false restore.
                string agentJsonPath = Path.Combine(ProgramDataDirectory, "agent.json");
                string gatewayCaPath = Path.Combine(ProgramDataDirectory, "certs", "gateway-ca.pem");
                JToken originalTunnel = null;
                string originalGatewayCaB64 = null;
                // Distinguishes "snapshot succeeded and found nothing" (safe to delete on rollback)
                // from "snapshot threw and we don't know what was there" (must NOT delete). Only set
                // true once BOTH reads below complete, so a mid-snapshot throw leaves it false.
                bool originalStateCaptured = false;
                try
                {
                    if (File.Exists(agentJsonPath))
                    {
                        JObject preRoot = JObject.Parse(File.ReadAllText(agentJsonPath));
                        if (preRoot["Tunnel"] is JObject preTunnel)
                        {
                            originalTunnel = preTunnel.DeepClone();
                        }
                    }

                    // gateway-ca.pem is a FIXED filename that `up` overwrites, so we must preserve
                    // any pre-existing copy. The {uuid}-cert.pem / {uuid}-key.pem files are uniquely
                    // named per enrollment, so they can never collide with a pre-existing config.
                    if (File.Exists(gatewayCaPath))
                    {
                        originalGatewayCaB64 = Convert.ToBase64String(File.ReadAllBytes(gatewayCaPath));
                    }

                    originalStateCaptured = true;
                }
                catch (Exception e)
                {
                    session.Log($"failed to snapshot pre-enrollment tunnel state (rollback will not restore): {e}");
                }

                // Only `--enrollment-string` is mandatory at enroll time. The signed
                // jet_agent_name claim is authoritative for the CSR, certificate CN, and
                // persisted config. Everything else (advertise subnets, advertise domains) is
                // patched into agent.json *after* enrollment, so we don't accumulate parallel CLI
                // surfaces for what is ultimately configuration data.
                //
                // The JWT is passed via stdin (sentinel `-`) to avoid exposing it in the process
                // command line (visible to any local process via WMI / Process Explorer / ETW).
                string arguments = "up --enrollment-string -";
                string Redact(string s) => s.Replace(enrollmentString, "***");
                session.Log($"Running enrollment: {exePath} {Redact(arguments)}");

                // The JWT goes to the child via stdin (sentinel `-` in the args), never the command
                // line — the bearer token would otherwise be visible to any local process via
                // WMI / Process Explorer / ETW.
                AgentRunResult enrollResult = RunAgentCommand(exePath, arguments, enrollmentString, ProgramDataDirectory, 60_000);

                if (enrollResult.TimedOut)
                {
                    // A hard Kill() bypasses the agent's own rollback and no marker exists yet, so a hang
                    // after `up` persisted its enrollment would orphan it; undo it (guarded so an early
                    // hang that wrote nothing can't delete the prior install's certs).
                    RollbackFailedEnrollment(session, agentJsonPath, originalTunnel, originalGatewayCaB64, originalStateCaptured);

                    return Fail("Agent tunnel enrollment timed out. Verify your Devolutions Gateway is reachable from this machine.");
                }

                if (!string.IsNullOrEmpty(enrollResult.Stdout))
                {
                    session.Log($"enrollment stdout: {Redact(enrollResult.Stdout)}");
                }
                if (!string.IsNullOrEmpty(enrollResult.Stderr))
                {
                    session.Log($"enrollment stderr: {Redact(enrollResult.Stderr)}");
                }

                if (enrollResult.ExitCode != 0)
                {
                    string detail = !string.IsNullOrWhiteSpace(enrollResult.Stderr) ? Redact(enrollResult.Stderr).Trim() : $"exit code {enrollResult.ExitCode}";

                    // `up` only enrolls, so a non-zero exit can leave a freshly-persisted enrollment
                    // on disk with no marker yet; undo it (guarded against early failures).
                    RollbackFailedEnrollment(session, agentJsonPath, originalTunnel, originalGatewayCaB64, originalStateCaptured);

                    return Fail($"Agent tunnel enrollment failed: {detail}");
                }

                // Enrollment succeeded and the agent has written agent.json + cert files. Record a
                // rollback marker capturing (a) the newly-written cert paths to clean up and (b) the
                // pre-enrollment Tunnel section / gateway-ca to restore. Written BEFORE
                // WriteTunnelAdvertisementsToConfig so that if that call throws (and triggers a
                // rollback), the marker already exists and rollback can undo what `up` wrote.
                //
                // The marker is REQUIRED for safe rollback — it's how the rollback CA knows what
                // THIS install wrote versus pre-existing state. So if we can't record it, we undo
                // the enrollment inline and fail now, rather than leaving artifacts a later rollback
                // (which keys off the marker) couldn't clean up.
                // Declared OUTSIDE the try so the catch can still pass whatever was collected
                // (possibly empty) to the inline cleanup.
                List<string> newCertPaths = new();
                try
                {
                    // Parse the freshly-written agent.json to learn what `up` wrote. This MUST live
                    // inside the same try as the marker write: if the read/parse throws and we let it
                    // fall through to the outer catch, we'd Fail() with neither a marker NOR an inline
                    // cleanup, orphaning the just-written cert/key/tunnel artifacts.
                    //
                    // Collect whatever the (best-effort) helper finds FIRST, so that if the
                    // completeness check below throws, the surrounding catch's inline cleanup gets
                    // whatever cert paths WERE written.
                    newCertPaths = ReadTunnelCertPaths(agentJsonPath);

                    // A successful `up` (exit 0) is a contract: agent.json MUST exist with a Tunnel
                    // section carrying all three cert paths. If any is missing the agent's behavior
                    // diverged — proceeding would write a marker whose NewCertPaths can't delete the
                    // cert/key, and (with no subnets/domains) the install would "succeed" with an
                    // unusable marker. ReadTunnelCertPaths only adds the three non-empty path fields,
                    // so fewer than three means agent.json/Tunnel/a path field was missing. Throw so
                    // the surrounding catch rolls back inline and Fail()s.
                    if (newCertPaths.Count != 3)
                    {
                        throw new Exception("agent tunnel enrollment reported success but agent.json is missing the expected Tunnel cert paths");
                    }

                    JArray markerCertPaths = new();
                    foreach (string p in newCertPaths)
                    {
                        markerCertPaths.Add(p);
                    }

                    JObject marker = new()
                    {
                        ["NewCertPaths"] = markerCertPaths,
                        ["OriginalTunnel"] = originalTunnel,
                        ["OriginalGatewayCaB64"] = originalGatewayCaB64,
                        ["OriginalStateCaptured"] = originalStateCaptured,
                    };

                    // Atomic write: a half-written marker is worse than none — rollback would fail
                    // to parse it and leave artifacts behind. WriteFileAtomic guarantees the marker
                    // is either fully present or absent.
                    WriteFileAtomic(markerPath, marker.ToString());

                    // Mirror CleanAgentConfig: schedule the marker for deletion at reboot so a
                    // successful install doesn't leave it lingering. Rollback deletes it eagerly.
                    WinAPI.MoveFileEx(markerPath, null, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);
                }
                catch (Exception e)
                {
                    session.Log($"failed to record tunnel rollback marker: {e}");
                    // No reliable marker => a later MSI rollback couldn't clean this enrollment up.
                    // Undo it inline and fail now so the machine is left as it was before enroll.
                    CleanUpEnrollmentArtifacts(session, newCertPaths, originalTunnel, originalGatewayCaB64, originalStateCaptured);
                    return Fail("Failed to record the agent tunnel rollback marker; the enrollment was rolled back.");
                }

                if (subnetsArg.Length != 0 || domainsArg.Length != 0)
                {
                    // Throws on a missing Tunnel section or write failure; the surrounding
                    // catch converts that into Fail(...) so we never report success while
                    // silently discarding operator-supplied subnets/domains.
                    WriteTunnelAdvertisementsToConfig(session, subnetsArg, domainsArg);
                }

                // Enrollment only proved the HTTPS/TCP path, but the tunnel runs over QUIC/UDP
                // (4433). Probe that path as a distinct step so a blocked UDP port fails the install
                // while the operator is still here to fix the firewall. The rollback marker is
                // already on disk, so a probe failure is undone by the marker-driven rollback.
                session.Log($"Running connectivity probe: {exePath} probe");
                AgentRunResult probeResult = RunAgentCommand(exePath, "probe", null, ProgramDataDirectory, 60_000);

                if (!string.IsNullOrEmpty(probeResult.Stdout))
                {
                    session.Log($"probe stdout: {probeResult.Stdout}");
                }
                if (!string.IsNullOrEmpty(probeResult.Stderr))
                {
                    session.Log($"probe stderr: {probeResult.Stderr}");
                }

                if (probeResult.TimedOut)
                {
                    return Fail("Agent tunnel connectivity probe timed out. The agent can't reach the Devolutions Gateway over UDP/QUIC (port 4433); check that the firewall allows it.");
                }

                if (probeResult.ExitCode != 0)
                {
                    string detail = !string.IsNullOrWhiteSpace(probeResult.Stderr) ? probeResult.Stderr.Trim() : $"exit code {probeResult.ExitCode}";
                    return Fail($"Agent tunnel connectivity probe failed: the agent could not establish the QUIC/UDP tunnel to the Devolutions Gateway (port 4433). If UDP is blocked, open it on the firewall. {detail}");
                }

                session.Log("Agent tunnel enrollment completed successfully");
                return ActionResult.Success;
            }
            catch (Exception e)
            {
                return Fail($"Agent tunnel enrollment failed: {e.Message}");
            }
        }

        // When TimedOut is true the child was killed, so ExitCode/Stdout/Stderr carry no meaning —
        // callers must check TimedOut first.
        private sealed class AgentRunResult
        {
            public bool TimedOut;
            public int ExitCode;
            public string Stdout;
            public string Stderr;
        }

        /// <summary>
        /// Runs an <c>agent.exe</c> subcommand to completion, feeding <paramref name="stdin"/> (if
        /// any) and capturing stdout/stderr. Kills the child and reports <see cref="AgentRunResult.TimedOut"/>
        /// if it doesn't exit within <paramref name="timeoutMs"/>.
        /// </summary>
        private static AgentRunResult RunAgentCommand(string exePath, string arguments, string stdin, string workingDirectory, int timeoutMs)
        {
            ProcessStartInfo startInfo = new(exePath, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
                WorkingDirectory = workingDirectory,
            };

            using Process process = Process.Start(startInfo);

            // Write stdin (if any) and close it so the child sees EOF. The payload is small and
            // stdin is closed immediately, so this can't block before we start draining the output
            // pipes below.
            if (stdin != null)
            {
                process.StandardInput.Write(stdin);
            }
            process.StandardInput.Close();

            // Drain stdout/stderr concurrently with the wait. The Windows anonymous-pipe buffer is
            // ~4 KB; if the child writes more than that (verbose logs, cert dumps) while we block in
            // WaitForExit before reading, the child blocks on write(), the wait never returns, and
            // we'd Kill() a healthy process — a spurious install failure. Starting the async readers
            // up front keeps the pipes drained.
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(timeoutMs))
            {
                try
                {
                    process.Kill();
                }
                catch
                {
                    // Already exited between WaitForExit timing out and Kill firing.
                }

                // The async readers may still be running against the (now disposing) streams.
                // Observe them with a bounded wait so their exceptions don't surface later as
                // unobserved task exceptions; swallow whatever they throw — we're already failing.
                try
                {
                    Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 5000);
                }
                catch
                {
                    // Observed.
                }

                return new AgentRunResult { TimedOut = true };
            }

            // Parameterless WaitForExit ensures the async stdout/stderr readers have fully flushed
            // before we read their results. GetAwaiter().GetResult() unwraps IO errors instead of
            // wrapping them in an AggregateException ("One or more errors occurred.").
            process.WaitForExit();

            return new AgentRunResult
            {
                TimedOut = false,
                ExitCode = process.ExitCode,
                Stdout = stdoutTask.GetAwaiter().GetResult(),
                Stderr = stderrTask.GetAwaiter().GetResult(),
            };
        }

        /// <summary>
        /// Patch the freshly-written agent.json's <c>Tunnel</c> section with the operator's
        /// advertised subnets and DNS suffixes from the wizard. Keeping this out of the
        /// <c>agent.exe up</c> command line means we only carry mandatory enroll inputs on the
        /// CLI; everything else flows through the same configuration file the agent reads at
        /// runtime.
        /// </summary>
        private static void WriteTunnelAdvertisementsToConfig(Session session, string subnetsCsv, string domainsCsv)
        {
            string[] subnets = SplitCsv(subnetsCsv);
            string[] domains = SplitCsv(domainsCsv);

            // Nothing operator-supplied to persist: stay a no-op. This path must never fail.
            if (subnets.Length == 0 && domains.Length == 0)
            {
                return;
            }

            string configPath = Path.Combine(ProgramDataDirectory, "agent.json");
            if (!File.Exists(configPath))
            {
                // The operator supplied subnets/domains but agent.json doesn't exist after a
                // successful `up`. Throwing surfaces this as a CA failure rather than silently
                // dropping their input and reporting install success.
                throw new Exception($"agent.json not found at {configPath}; cannot persist advertised subnets/domains");
            }

            JObject root = JObject.Parse(File.ReadAllText(configPath));

            // ConfFile uses serde rename_all = "PascalCase", so the tunnel section is keyed
            // "Tunnel" and the fields are "AdvertiseSubnets" / "AdvertiseDomains".
            if (root["Tunnel"] is not JObject tunnel)
            {
                // Fail loud: a missing Tunnel section after a successful `up` means the agent's
                // enrollment behavior diverged from what this CA assumes. Silently skipping the
                // write here would discard operator-supplied advertisements while reporting
                // install success — we want to catch the divergence, not hide it.
                throw new Exception("agent.json has no Tunnel section after enrollment; cannot persist advertised subnets/domains");
            }

            if (subnets.Length != 0)
            {
                tunnel["AdvertiseSubnets"] = new JArray(subnets);
            }
            if (domains.Length != 0)
            {
                tunnel["AdvertiseDomains"] = new JArray(domains);
            }

            // Let genuine IO/parse errors propagate too: swallowing them would also lose the
            // operator's data while falsely reporting success. Write atomically so a mid-write
            // failure can't truncate agent.json — the rollback path re-parses it to restore the
            // original Tunnel section, which a half-written file would make impossible.
            // Pass an explicit JsonConverter[]: the single-argument ToString(Formatting) overload only exists in
            // Newtonsoft.Json 13.0.4+ and crashes with MissingMethodException against an older 13.x in the GAC.
            // See the detailed note in ToggleAgentFeature and Newtonsoft.Json issue #3084.
            WriteFileAtomic(configPath, root.ToString(Formatting.Indented, Array.Empty<JsonConverter>()));
            session.Log($"Wrote {subnets.Length} advertise_subnets and {domains.Length} advertise_domains entries to agent.json");
        }

        /// <summary>
        /// Write a file atomically: serialize to a sibling temp file, then replace the target in
        /// one step. A failure mid-write never truncates or corrupts the existing file — the
        /// original stays intact until the atomic replace. Used for every agent.json write on the
        /// enrollment/rollback path so the rollback can always re-parse agent.json.
        /// </summary>
        private static void WriteFileAtomic(string path, string contents)
        {
            WriteFileAtomicCore(path, tmpPath => File.WriteAllText(tmpPath, contents));
        }

        /// <summary>
        /// Byte-oriented sibling of <see cref="WriteFileAtomic(string, string)"/>. Used to restore
        /// the snapshotted gateway-ca.pem during rollback so the restore can't truncate the target
        /// if it fails mid-write.
        /// </summary>
        private static void WriteFileAtomic(string path, byte[] contents)
        {
            WriteFileAtomicCore(path, tmpPath => File.WriteAllBytes(tmpPath, contents));
        }

        /// <summary>
        /// Shared atomic-write core: write to a sibling temp file via <paramref name="writeTemp"/>,
        /// then atomically replace (or move) onto the target. If anything after the temp write
        /// fails, the temp file is deleted before the exception propagates so we never leave a
        /// stray <c>.tmp</c> behind.
        /// </summary>
        private static void WriteFileAtomicCore(string path, Action<string> writeTemp)
        {
            string tmpPath = path + ".tmp";

            try
            {
                writeTemp(tmpPath);

                if (File.Exists(path))
                {
                    // File.Replace performs an atomic NTFS replace (no backup file requested).
                    File.Replace(tmpPath, path, null);
                }
                else
                {
                    File.Move(tmpPath, path);
                }
            }
            catch
            {
                try
                {
                    if (File.Exists(tmpPath))
                    {
                        File.Delete(tmpPath);
                    }
                }
                catch
                {
                    // Best-effort cleanup; surface the original failure below.
                }

                throw;
            }
        }

        private static string[] SplitCsv(string csv) =>
            (csv ?? string.Empty)
                .Split(',')
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToArray();

        [CustomAction]
        public static ActionResult ConfigureFeatures(Session session)
        {
            string featuresToConfigure = session.Property(AgentProperties.featuresToConfigure.Id);
            HashSet<string> enabledFeatures = new HashSet<string>(
                featuresToConfigure.Split([','], StringSplitOptions.RemoveEmptyEntries));

            string[] allFeatureJsonIds =
            [
                Features.SESSION_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length),
                Features.AGENT_UPDATER_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length),
                Features.PSU_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length),
                Features.PEDM_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length),
            ];

            foreach (string featureJsonId in allFeatureJsonIds)
            {
                ActionResult result = ToggleAgentFeature(session, featureJsonId, enabledFeatures.Contains(featureJsonId));

                if (result != ActionResult.Success)
                {
                    return result;
                }
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

        /// <summary>
        /// Undo a completed tunnel enrollment: delete the uniquely-named client cert/key, restore
        /// (or delete) the fixed-name gateway-ca.pem, and restore (or remove) the Tunnel section in
        /// agent.json. Shared by the marker-driven rollback CA and by EnrollAgentTunnel's inline
        /// cleanup when it cannot record the rollback marker. Best-effort: logs and continues past
        /// individual failures so it never aborts a rollback.
        /// </summary>
        // Only undo when `up` actually persisted a NEW enrollment (client cert path changed from the
        // pre-`up` snapshot); else an early failure would delete the prior install's still-referenced certs.
        private static void RollbackFailedEnrollment(Session session, string agentJsonPath, JToken originalTunnel, string originalGatewayCaB64, bool originalStateCaptured)
        {
            if (!originalStateCaptured)
            {
                // Snapshot failed, so we can't tell new artifacts from the prior install's — skip
                // rather than risk deleting cert/key we never observed (a harmless orphan beats deletion).
                session.Log("skipping enrollment cleanup: pre-enrollment state was not captured");
                return;
            }

            List<string> certPaths = ReadTunnelCertPaths(agentJsonPath);
            string originalClientCert = originalTunnel?["ClientCertPath"]?.Value<string>();
            string currentClientCert = certPaths.FirstOrDefault(p => p.EndsWith("-cert.pem", StringComparison.OrdinalIgnoreCase));

            if (currentClientCert != null && !string.Equals(currentClientCert, originalClientCert, StringComparison.OrdinalIgnoreCase))
            {
                CleanUpEnrollmentArtifacts(session, certPaths, originalTunnel, originalGatewayCaB64, originalStateCaptured);
            }
            else
            {
                session.Log("skipping enrollment cleanup: `up` did not persist a new enrollment (client cert unchanged)");
            }
        }

        private static void CleanUpEnrollmentArtifacts(Session session, List<string> newCertPaths, JToken originalTunnel, string originalGatewayCaB64, bool originalStateCaptured)
        {
            // The client cert/key are uniquely named per enrollment, so they're always deleted —
            // they can't collide with pre-existing state. gateway-ca.pem and the Tunnel section are
            // fixed-name/shared, so they're only touched when we actually captured the pre-enrollment
            // state; if the snapshot threw (originalStateCaptured == false), null is ambiguous
            // (absent vs failed-to-read) and we must leave those shared artifacts untouched rather
            // than delete state we never observed.
            foreach (string certPath in newCertPaths)
            {
                if (string.IsNullOrEmpty(certPath))
                {
                    continue;
                }

                bool isGatewayCa = certPath.EndsWith("gateway-ca.pem", StringComparison.OrdinalIgnoreCase);

                if (isGatewayCa)
                {
                    if (!originalStateCaptured)
                    {
                        // Snapshot failed: we don't know whether a pre-existing gateway-ca.pem was
                        // here, so leave it untouched (neither restore nor delete).
                        session.Log($"skipping gateway-ca cleanup at {certPath}; pre-enrollment state was not captured");
                        continue;
                    }

                    if (originalGatewayCaB64 != null)
                    {
                        // Restore to the ACTUAL path `up` wrote (from the marker), atomically so a
                        // failed restore can't truncate it.
                        try
                        {
                            WriteFileAtomic(certPath, Convert.FromBase64String(originalGatewayCaB64));
                            session.Log($"restored pre-existing gateway-ca.pem at {certPath}");
                        }
                        catch (Exception e)
                        {
                            session.Log($"failed to restore gateway-ca.pem at {certPath}: {e}");
                        }
                    }
                    else
                    {
                        // Captured, and there was no pre-existing copy: delete what `up` wrote.
                        try
                        {
                            if (File.Exists(certPath))
                            {
                                File.Delete(certPath);
                                session.Log($"removed orphaned gateway-ca.pem {certPath}");
                            }
                        }
                        catch (Exception e)
                        {
                            session.Log($"failed to delete gateway-ca.pem {certPath}: {e}");
                        }
                    }

                    continue;
                }

                try
                {
                    if (File.Exists(certPath))
                    {
                        File.Delete(certPath);
                        session.Log($"removed orphaned enrollment artifact {certPath}");
                    }
                }
                catch (Exception e)
                {
                    session.Log($"failed to delete enrollment artifact {certPath}: {e}");
                }
            }

            // Tunnel section in agent.json: only touch it when the pre-enrollment state was
            // captured. If the snapshot threw, a null originalTunnel is ambiguous (no Tunnel vs
            // failed-to-read) and removing it could destroy a pre-existing section, so skip the
            // read/modify/write entirely.
            if (!originalStateCaptured)
            {
                session.Log("skipping Tunnel section cleanup in agent.json; pre-enrollment state was not captured");
                return;
            }

            // Restore the pre-enrollment Tunnel section: put back the original if one was
            // snapshotted, otherwise remove the section the enrollment introduced. The agent.json
            // write is atomic so a mid-write failure can't corrupt it.
            string configPath = Path.Combine(ProgramDataDirectory, "agent.json");
            try
            {
                if (File.Exists(configPath))
                {
                    JObject root = JObject.Parse(File.ReadAllText(configPath));

                    if (originalTunnel != null && originalTunnel.Type != JTokenType.Null)
                    {
                        root["Tunnel"] = originalTunnel.DeepClone();
                        session.Log("restored pre-enrollment Tunnel section in agent.json");
                    }
                    else
                    {
                        root.Remove("Tunnel");
                        session.Log("removed Tunnel section from agent.json during enrollment rollback");
                    }

                    // Pass an explicit JsonConverter[]: the single-argument ToString(Formatting) overload only exists
                    // in Newtonsoft.Json 13.0.4+ and crashes with MissingMethodException against an older 13.x in the
                    // GAC. See the detailed note in ToggleAgentFeature and Newtonsoft.Json issue #3084.
                    WriteFileAtomic(configPath, root.ToString(Formatting.Indented, Array.Empty<JsonConverter>()));
                }
            }
            catch (Exception e)
            {
                session.Log($"failed to restore Tunnel section in agent.json: {e}");
            }
        }

        // Pairs with EnrollAgentTunnel. On a successful enrollment the agent writes cert/key files
        // into %ProgramData%\Devolutions\Agent\certs\ and a Tunnel section into agent.json. None of
        // these are MSI-managed components, so if a later install action fails and MSI rolls back,
        // those artifacts would be orphaned on disk.
        //
        // This rollback CA is MARKER-DRIVEN. EnrollAgentTunnel only writes the marker once
        // enrollment succeeds, and it snapshots the pre-enrollment Tunnel section + the fixed-name
        // gateway-ca.pem into that marker first. That distinction matters: rollback fires for ANY
        // MSI rollback, including when the forward action failed BEFORE writing anything (empty
        // enrollment string, or `agent.exe up` returning non-zero). In those cases the current
        // Tunnel section / certs are PRE-EXISTING (manual config or old residue) and must NOT be
        // touched — the absence of the marker is exactly what tells us that. When the marker is
        // present we delete the freshly-written {uuid}-cert/key.pem, restore-or-delete the
        // fixed-name gateway-ca.pem, and restore-or-remove the Tunnel section. Everything is
        // best-effort and always returns Success so it never aborts the rollback chain.
        [CustomAction]
        public static ActionResult RollbackEnrollAgentTunnel(Session session)
        {
            string installId = session.Get(AgentProperties.installId).ToString();
            string markerPath = Path.Combine(Path.GetTempPath(), $"{installId}-tunnel-rollback.json");

            // No marker => the forward action never reached its write phase, so the current Tunnel
            // section / certs are pre-existing and we must leave them untouched. This is the core
            // fix for the over-eager deletion the reviewer flagged.
            if (!File.Exists(markerPath))
            {
                session.Log($"no tunnel rollback marker at {markerPath}; enrollment never completed its write phase, nothing to roll back");
                return ActionResult.Success;
            }

            JObject marker;
            try
            {
                marker = JObject.Parse(File.ReadAllText(markerPath));
            }
            catch (Exception e)
            {
                session.Log($"failed to parse tunnel rollback marker at {markerPath}: {e}");
                return ActionResult.Success;
            }

            List<string> newCertPaths = new();
            if (marker["NewCertPaths"] is JArray markerCertPaths)
            {
                foreach (JToken entry in markerCertPaths)
                {
                    string certPath = entry?.Value<string>();
                    if (!string.IsNullOrEmpty(certPath))
                    {
                        newCertPaths.Add(certPath);
                    }
                }
            }

            bool originalStateCaptured = marker["OriginalStateCaptured"]?.Value<bool>() ?? false;

            CleanUpEnrollmentArtifacts(session, newCertPaths, marker["OriginalTunnel"], marker["OriginalGatewayCaB64"]?.Value<string>(), originalStateCaptured);

            try
            {
                File.Delete(markerPath);
            }
            catch (Exception e)
            {
                session.Log($"failed to delete tunnel rollback marker at {markerPath}: {e}");
            }

            // Best effort, always return success
            return ActionResult.Success;
        }

        /// <summary>
        /// Validate that a PSU server URL is an absolute http/https URL. The agent deserializes this
        /// value as a <c>url::Url</c> and connects to it as a gRPC endpoint, so malformed or non-http(s)
        /// input must be rejected before it reaches agent.json; otherwise the first service start after
        /// installation fails.
        /// </summary>
        public static bool IsValidPsuServerUrl(string value)
        {
            return Uri.TryCreate(value, UriKind.Absolute, out Uri uri)
                && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
        }

        /// <summary>
        /// Best-effort connectivity probe against a PSU server URL, used for early diagnostics before
        /// the configuration is written. Opens a TCP connection to the URL's host and port (a plain
        /// HTTP request would be misleading against an HTTP/2-only gRPC endpoint) and returns whether
        /// it succeeded within <paramref name="timeoutMs"/>. Never throws.
        /// </summary>
        public static bool TryReachPsuServer(string value, int timeoutMs, out string error)
        {
            error = null;

            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri uri))
            {
                error = "the URL is not a valid absolute URL";
                return false;
            }

            int port = uri.Port >= 0 ? uri.Port : (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80);

            try
            {
                using System.Net.Sockets.TcpClient client = new();
                Task connectTask = client.ConnectAsync(uri.Host, port);
                if (!connectTask.Wait(timeoutMs))
                {
                    error = $"connection to {uri.Host}:{port} timed out after {timeoutMs} ms";
                    return false;
                }

                // Wait already observed completion; surface any connection exception.
                connectTask.GetAwaiter().GetResult();
                return true;
            }
            catch (Exception e)
            {
                Exception inner = (e as AggregateException)?.GetBaseException() ?? e;
                error = $"could not reach {uri.Host}:{port} ({inner.Message})";
                return false;
            }
        }

        /// <summary>
        /// Whether agent.json already holds a complete <c>PsuAgent</c> section (both a non-empty
        /// <c>ServerUrl</c> and <c>AppToken</c>). Used to preserve an existing configuration on a
        /// silent upgrade that re-runs <see cref="ConfigurePsuAgent"/> without passing PSU
        /// properties. Best-effort: any read/parse failure is treated as "not complete".
        /// </summary>
        private static bool PsuConfigIsComplete(string configPath)
        {
            try
            {
                if (!File.Exists(configPath))
                {
                    return false;
                }

                if (JObject.Parse(File.ReadAllText(configPath))["PsuAgent"] is not JObject psu)
                {
                    return false;
                }

                return !string.IsNullOrWhiteSpace((string)psu["ServerUrl"])
                    && !string.IsNullOrWhiteSpace((string)psu["AppToken"]);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Persist the PowerShell Universal agent configuration collected in <c>PsuDialog</c> into
        /// agent.json's <c>PsuAgent</c> section. The generic <see cref="ConfigureFeatures"/> action
        /// toggles <c>PsuAgent.Enabled</c>; this action fills the remaining required/optional fields
        /// so the agent can start. The app token is written verbatim, or as a <c>$secret:&lt;name&gt;</c>
        /// reference when the operator chose "Secret name", so it is resolved from SecretManagement at runtime.
        /// </summary>
        [CustomAction]
        public static ActionResult ConfigurePsuAgent(Session session)
        {
            // Both the URL and the app token are Base64-encoded into CustomActionData (see
            // EncodePropertyData) because an arbitrary value can contain the ';' or '=' delimiters
            // (a URL may embed them in a path or query parameter); decode them here.
            string serverUrl = WixProperties.Decode(session, AgentProperties.psuServerUrl)?.Trim() ?? string.Empty;
            string appToken = WixProperties.Decode(session, AgentProperties.psuAppToken)?.Trim() ?? string.Empty;
            bool isSecretReference = string.Equals(
                session.Property(AgentProperties.psuAppTokenIsSecretReference.Id)?.Trim(),
                "true",
                StringComparison.OrdinalIgnoreCase);
            string agentId = session.Property(AgentProperties.psuAgentId.Id)?.Trim() ?? string.Empty;
            string displayName = session.Property(AgentProperties.psuDisplayName.Id)?.Trim() ?? string.Empty;

            ActionResult Fail(string msg)
            {
                session.Log(msg);
                using Record record = new(0) { FormatString = msg };
                session.Message(InstallMessage.Error, record);
                return ActionResult.Failure;
            }

            string configPath = Path.Combine(ProgramDataDirectory, "agent.json");

            // A silent major upgrade migrates this feature and re-runs this action, but the agent
            // self-updater invokes `msiexec /quiet` without any PSU properties. On that path we do
            // not receive the current token, so we must neither rewrite (which would wipe the config)
            // nor fail (which would roll back every future upgrade). When no PSU properties are
            // supplied and agent.json already holds a complete configuration, preserve it as-is. The
            // required-field checks below still apply when the feature is newly selected.
            if (serverUrl.Length == 0 && appToken.Length == 0 && PsuConfigIsComplete(configPath))
            {
                session.Log("No PowerShell Universal properties supplied; preserving the existing configuration in agent.json");
                return ActionResult.Success;
            }

            // Both are required for a config the agent can start with. The dialog enforces this in
            // the UI; for a silent install the operator must pass P.PSUSERVERURL and P.PSUAPPTOKEN.
            if (serverUrl.Length == 0)
            {
                return Fail("A PowerShell Universal server URL is required (P.PSUSERVERURL), or deselect the PowerShell Universal Agent feature.");
            }

            if (appToken.Length == 0)
            {
                return Fail("A PowerShell Universal app token is required (P.PSUAPPTOKEN), or deselect the PowerShell Universal Agent feature.");
            }

            // Reject a malformed URL here (both the UI and silent-install paths land in this action)
            // so we never write a value the agent can't parse as a url::Url at service start.
            if (!IsValidPsuServerUrl(serverUrl))
            {
                return Fail("The PowerShell Universal server URL (P.PSUSERVERURL) must be an absolute http or https URL, for example http://localhost:5000.");
            }

            try
            {
                string installId = session.Get(AgentProperties.installId).ToString();
                string markerPath = Path.Combine(Path.GetTempPath(), $"{installId}-psu-rollback.json");

                // Snapshot the pre-existing PsuAgent section BEFORE we patch it so rollback can restore it.
                // Best-effort: on any failure the snapshot stays null and rollback removes the section
                // (the safe direction is no false restore). originalStateCaptured distinguishes
                // "snapshot succeeded and found nothing" from "snapshot threw".
                JToken originalPsu = null;
                bool originalStateCaptured = false;
                try
                {
                    if (File.Exists(configPath))
                    {
                        JObject preRoot = JObject.Parse(File.ReadAllText(configPath));
                        if (preRoot["PsuAgent"] is JObject prePsu)
                        {
                            originalPsu = prePsu.DeepClone();
                        }
                    }

                    originalStateCaptured = true;
                }
                catch (Exception e)
                {
                    session.Log($"failed to snapshot pre-existing PSU config (rollback will not restore): {e}");
                }

                // Only start from an empty object when agent.json is genuinely absent. If the file
                // exists but can't be read or parsed (permission, sharing, corruption), let the
                // exception reach the outer failure handler instead of silently overwriting it — an
                // atomic write of a PSU-only object here would drop tunnel certs and every other setting.
                JObject config;
                if (File.Exists(configPath))
                {
                    config = JObject.Parse(File.ReadAllText(configPath));
                }
                else
                {
                    config = new JObject();
                }

                // Record the rollback marker BEFORE writing so an MSI rollback triggered by a later
                // action can restore the original PsuAgent section. The marker is keyed by installId and
                // scheduled for deletion at reboot; the rollback CA deletes it eagerly.
                try
                {
                    JObject marker = new()
                    {
                        ["OriginalPsu"] = originalPsu,
                        ["OriginalStateCaptured"] = originalStateCaptured,
                    };

                    WriteFileAtomic(markerPath, marker.ToString(Formatting.None, Array.Empty<JsonConverter>()));
                    WinAPI.MoveFileEx(markerPath, null, WinAPI.MOVEFILE_DELAY_UNTIL_REBOOT);
                }
                catch (Exception e)
                {
                    return Fail($"Failed to record the PowerShell Universal rollback marker: {e.Message}");
                }

                // Merge into the existing PSU section so the Enabled flag written by ConfigureFeatures
                // (and any unmanaged fields) are preserved.
                if (config["PsuAgent"] is not JObject psu)
                {
                    psu = new JObject();
                    config["PsuAgent"] = psu;
                }

                // ConfFile uses serde rename_all = "PascalCase", so fields are keyed in PascalCase.
                psu["ServerUrl"] = serverUrl;
                psu["AppToken"] = isSecretReference ? $"$secret:{appToken}" : appToken;

                if (agentId.Length != 0)
                {
                    psu["AgentId"] = agentId;
                }
                else
                {
                    psu.Remove("AgentId");
                }

                if (displayName.Length != 0)
                {
                    psu["DisplayName"] = displayName;
                }
                else
                {
                    psu.Remove("DisplayName");
                }

                // Two-argument ToString(Formatting, JsonConverter[]) — see the detailed Newtonsoft
                // GAC-version note in ToggleAgentFeature. Written atomically so a mid-write failure
                // can't truncate agent.json (rollback re-parses it to restore the original section).
                WriteFileAtomic(configPath, config.ToString(Formatting.None, Array.Empty<JsonConverter>()));

                session.Log("Wrote PowerShell Universal agent configuration to agent.json");
                return ActionResult.Success;
            }
            catch (Exception e)
            {
                return Fail($"Failed to configure the PowerShell Universal agent: {e.Message}");
            }
        }

        /// <summary>
        /// Undo a <see cref="ConfigurePsuAgent"/> write if a later install action triggers an MSI
        /// rollback. Marker-driven: it only restores/removes the <c>PsuAgent</c> section when
        /// ConfigurePsuAgent recorded a per-install marker, so it never touches a pre-existing
        /// section left by an unrelated run.
        /// </summary>
        [CustomAction]
        public static ActionResult RollbackConfigurePsuAgent(Session session)
        {
            string installId = session.Get(AgentProperties.installId).ToString();
            string markerPath = Path.Combine(Path.GetTempPath(), $"{installId}-psu-rollback.json");

            if (!File.Exists(markerPath))
            {
                session.Log($"no PSU rollback marker at {markerPath}; nothing to roll back");
                return ActionResult.Success;
            }

            JObject marker;
            try
            {
                marker = JObject.Parse(File.ReadAllText(markerPath));
            }
            catch (Exception e)
            {
                session.Log($"failed to parse PSU rollback marker at {markerPath}: {e}");
                return ActionResult.Success;
            }

            bool originalStateCaptured = marker["OriginalStateCaptured"]?.Value<bool>() ?? false;
            JToken originalPsu = marker["OriginalPsu"];

            // Only touch agent.json when the snapshot is trustworthy. If the snapshot threw during the
            // forward action we don't know the prior state, so we leave the file untouched.
            if (originalStateCaptured)
            {
                try
                {
                    string configPath = Path.Combine(ProgramDataDirectory, "agent.json");
                    if (File.Exists(configPath))
                    {
                        JObject config = JObject.Parse(File.ReadAllText(configPath));

                        if (originalPsu != null && originalPsu.Type == JTokenType.Object)
                        {
                            config["PsuAgent"] = originalPsu;
                        }
                        else
                        {
                            // There was no PSU section before this install wrote one: remove it.
                            config.Remove("PsuAgent");
                        }

                        WriteFileAtomic(configPath, config.ToString(Formatting.None, Array.Empty<JsonConverter>()));
                        session.Log("Restored the pre-install PSU section in agent.json");
                    }
                }
                catch (Exception e)
                {
                    session.Log($"failed to restore PsuAgent section during rollback: {e}");
                }
            }

            try
            {
                File.Delete(markerPath);
            }
            catch (Exception e)
            {
                session.Log($"failed to delete PSU rollback marker at {markerPath}: {e}");
            }

            // Best effort, always return success.
            return ActionResult.Success;
        }

        /// <summary>
        /// Delete the PSU rollback marker once the transaction commits successfully. The marker holds
        /// the pre-install <c>PsuAgent</c> section, which can include a plaintext <c>AppToken</c>, so it
        /// must not linger in the temp directory after a successful install (it is otherwise only
        /// removed at the next reboot, which may never happen). <see cref="RollbackConfigurePsuAgent"/>
        /// deletes it on failure; this commit action deletes it on success.
        /// </summary>
        [CustomAction]
        public static ActionResult CommitConfigurePsuAgent(Session session)
        {
            string installId = session.Get(AgentProperties.installId).ToString();
            string markerPath = Path.Combine(Path.GetTempPath(), $"{installId}-psu-rollback.json");

            try
            {
                if (File.Exists(markerPath))
                {
                    File.Delete(markerPath);
                    session.Log($"deleted PSU rollback marker at {markerPath}");
                }
            }
            catch (Exception e)
            {
                session.Log($"failed to delete PSU rollback marker at {markerPath}: {e}");
            }

            // Best effort, always return success.
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult SetInstallId(Session session)
        {
            session.Set(AgentProperties.installId, Guid.NewGuid());
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult EncodePropertyData(Session session)
        {
            // Base64-encode arbitrary/secret string properties into their "*_ENCODED" companion so
            // a value containing ';' or '=' (the CustomActionData delimiters) survives the trip to
            // the deferred action intact. Mirrors the gateway installer's EncodePropertyData.
            foreach (IWixProperty property in AgentProperties.Properties.Where(p => p.Encode))
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
