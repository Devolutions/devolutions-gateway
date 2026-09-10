using DevolutionsAgent;
using DevolutionsAgent.Actions;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using WixSharp;
using Xunit;
using Action = WixSharp.Action;
using File = System.IO.File;
using RegistryHive = WixSharp.RegistryHive;

namespace DevolutionsAgent.Installer.Tests;

public sealed class PackageBrokerInstallerTests
{
    [Fact]
    public void DedicatedPolicyAclAcceptsOnlySystemAndAdministrators()
    {
        DirectorySecurity security =
            DirectorySecurity(DevolutionsAgent.Resources.Includes.PROGRAM_DATA_PACKAGE_BROKER_SDDL);

        PackageBrokerPolicyActions.VerifyPackageBrokerSecurity(security);
        PackageBrokerPolicyActions.VerifySecurityDescriptor(
            security,
            DevolutionsAgent.Resources.Includes.PROGRAM_DATA_PACKAGE_BROKER_SDDL);
    }

    [Theory]
    [InlineData("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;LS)")]
    [InlineData("O:SYG:SYD:AI(A;;FA;;;SY)(A;;FA;;;BA)")]
    [InlineData("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;LS)")]
    public void DedicatedPolicyAclRejectsAnythingOutsideStrictContract(string sddl)
    {
        Assert.Throws<InvalidOperationException>(
            () => PackageBrokerPolicyActions.VerifyPackageBrokerSecurity(Security(sddl)));
    }

    [Theory]
    [InlineData("O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;LS)")]
    [InlineData("O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)")]
    public void LegacySourceAllowsTrustedOwnerAndUntrustedRead(string sddl)
    {
        Assert.True(
            PackageBrokerPolicyActions.TryVerifyLegacyPolicySourceSecurity(
                Security(sddl),
                out string diagnostic),
            diagnostic);
    }

    [Theory]
    [InlineData("GW", "LS")]
    [InlineData("0x2", "LS")]
    [InlineData("GA", "BU")]
    [InlineData("WD", "AU")]
    [InlineData("WO", "LS")]
    [InlineData("DC", "BU")]
    public void LegacySourceRejectsUntrustedWriteOrTamperRights(string rights, string sid)
    {
        FileSecurity security = Security($"O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;{rights};;;{sid})");

        Assert.False(
            PackageBrokerPolicyActions.TryVerifyLegacyPolicySourceSecurity(
                security,
                out string diagnostic));
        Assert.Contains("unsafe write or tamper rights", diagnostic);
    }

    [Fact]
    public void LegacySourceRejectsUntrustedOwner()
    {
        FileSecurity security = Security("O:BUG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)");

        Assert.False(
            PackageBrokerPolicyActions.TryVerifyLegacyPolicySourceSecurity(
                security,
                out string diagnostic));
        Assert.Contains("untrusted owner", diagnostic);
    }

    [Theory]
    [InlineData("O:SYG:SY")]
    [InlineData("O:SYG:SYD:P")]
    public void LegacySourceRejectsNullOrEmptyDacl(string sddl)
    {
        Assert.False(
            PackageBrokerPolicyActions.TryVerifyLegacyPolicySourceSecurity(
                Security(sddl),
                out string diagnostic));
        Assert.Contains("DACL", diagnostic);
    }

    [Theory]
    [InlineData("O:SYG:SY")]
    [InlineData("O:SYG:SYD:P")]
    public void TrustedAncestorRejectsNullOrEmptyDacl(string sddl)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => PackageBrokerPolicyActions.VerifyTrustedDirectorySecurity(
                DirectorySecurity(sddl)));
        Assert.Contains("DACL", error.Message);
    }

    [Fact]
    public void StrictConfigWithoutPolicyPathAllowsSourceCleanup()
    {
        Assert.True(
            PackageBrokerPolicyActions.TryReadConfiguredPolicyPath(
                """{"PackageBroker":{}}""",
                out string configuredPath,
                out string diagnostic),
            diagnostic);
        Assert.Null(configuredPath);
    }

    [Fact]
    public void StrictConfigReturnsAbsoluteJsonPolicyPath()
    {
        const string path = @"C:\ProgramData\Devolutions\Agent\package-broker-policy.json";

        Assert.True(
            PackageBrokerPolicyActions.TryReadConfiguredPolicyPath(
                $"{{\"PackageBroker\":{{\"PolicyPath\":\"{path.Replace(@"\", @"\\")}\"}}}}",
                out string configuredPath,
                out string diagnostic),
            diagnostic);
        Assert.Equal(path, configuredPath);
    }

    [Theory]
    [InlineData(@"\\server\share\policy.json")]
    [InlineData(@"\policy.json")]
    [InlineData(@"C:policy.json")]
    [InlineData(@"\\?\UNC\server\share\policy.json")]
    [InlineData(@"\??\UNC\server\share\policy.json")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\policy.json")]
    [InlineData(@"\\.\C:\policy.json")]
    [InlineData(@"\Device\HarddiskVolume1\policy.json")]
    [InlineData(@"C:\policy.json:stream")]
    [InlineData(@"C:\folder\..\policy.json")]
    [InlineData(@"C:\folder\\policy.json")]
    [InlineData(@"C:\policy.yaml")]
    public void ConfiguredPolicyPathRejectsUnsafeOrRemoteShapesBeforeProbe(string path)
    {
        Assert.False(
            PackageBrokerPolicyActions.TryValidateConfiguredLocalPolicyPath(
                path,
                out string diagnostic));
        Assert.False(string.IsNullOrWhiteSpace(diagnostic));
    }

    [Fact]
    public void ConfiguredPolicyPathAcceptsLocalVolumeGuid()
    {
        string volumeRoot = GetSystemVolumeGuidRoot();
        string path = $"{volumeRoot}Devolutions\\PackageBroker\\policy.json";

        Assert.True(
            PackageBrokerPolicyActions.TryValidateConfiguredLocalPolicyPath(
                path,
                out string diagnostic),
            diagnostic);
    }

    [Theory]
    [InlineData("""{"PackageBroker":{"PolicyPath":"C:\\policy.json",},}""")]
    [InlineData("""{"PackageBroker":{/*comment*/"PolicyPath":"C:\\policy.json"}}""")]
    [InlineData("""{'PackageBroker':{'PolicyPath':'C:\\policy.json'}}""")]
    [InlineData("""{PackageBroker:{PolicyPath:"C:\\policy.json"}}""")]
    [InlineData("""{"PackageBroker":{"PolicyPath":"C:\\first.json","PolicyPath":"C:\\second.json"}}""")]
    [InlineData("""{"PackageBroker":{}} {}""")]
    [InlineData("""{"PackageBroker":{"PolicyPath":42}}""")]
    [InlineData("""{"PackageBroker":{"PolicyPath":"relative.json"}}""")]
    public void AmbiguousConfigPreservesLegacySource(string json)
    {
        Assert.False(
            PackageBrokerPolicyActions.TryReadConfiguredPolicyPath(
                json,
                out _,
                out string diagnostic));
        Assert.False(string.IsNullOrWhiteSpace(diagnostic));
    }

    [Fact]
    public void MigrationMarkerRoundTripsAllBindings()
    {
        PackageBrokerPolicyActions.MigrationRecord record =
            new("source-id", "source-digest", "destination-id", "destination-digest");

        PackageBrokerPolicyActions.MigrationRecord parsed =
            PackageBrokerPolicyActions.ReadMigrationMarkerJson(record.ToJson());

        Assert.Equal(record.SourceIdentity, parsed.SourceIdentity);
        Assert.Equal(record.SourceDigest, parsed.SourceDigest);
        Assert.Equal(record.DestinationIdentity, parsed.DestinationIdentity);
        Assert.Equal(record.DestinationDigest, parsed.DestinationDigest);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"SourceIdentity":"id","SourceDigest":"digest"}""")]
    public void MigrationMarkerRejectsIncompleteBindings(string json)
    {
        Assert.Throws<InvalidOperationException>(
            () => PackageBrokerPolicyActions.ReadMigrationMarkerJson(json));
    }

    [Fact]
    public void PinnedFileIdentityAndDigestDetectContentMutation()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "policy.json");
        File.WriteAllText(path, "before");

        string identity;
        string digest;
        using (PackageBrokerPolicyActions.PinnedPath pinned = PinFile(path, WinAPI.GENERIC_READ))
        {
            identity = PackageBrokerPolicyActions.FileIdentity(pinned.Leaf);
            digest = PackageBrokerPolicyActions.FileContentDigest(pinned.Leaf);
            Assert.True(PackageBrokerPolicyActions.FileIdentityAndDigestMatch(pinned.Leaf, identity, digest));
        }

        File.WriteAllText(path, "after");
        using PackageBrokerPolicyActions.PinnedPath changed = PinFile(path, WinAPI.GENERIC_READ);
        Assert.Equal(identity, PackageBrokerPolicyActions.FileIdentity(changed.Leaf));
        Assert.False(PackageBrokerPolicyActions.FileIdentityAndDigestMatch(changed.Leaf, identity, digest));
    }

    [Fact]
    public void MissingPinnedLeafDoesNotCreateIt()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "missing.json");

        using PackageBrokerPolicyActions.PinnedPath pinned =
            PackageBrokerPolicyActions.PinPathWithoutReparse(
                path,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.FILE_READ_ATTRIBUTES);

        Assert.Null(pinned.Leaf);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void HandleTargetedDeletionDeletesPinnedFile()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "delete.json");
        File.WriteAllText(path, "{}");

        using (PackageBrokerPolicyActions.PinnedPath pinned = PinFile(
            path,
            WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES))
        {
            string identity = PackageBrokerPolicyActions.FileIdentity(pinned.Leaf);
            string digest = PackageBrokerPolicyActions.FileContentDigest(pinned.Leaf);
            Assert.True(
                PackageBrokerPolicyActions.DeleteFileIfIdentityAndDigestMatch(
                    pinned.Leaf,
                    identity,
                    digest));
        }

        Assert.False(File.Exists(path));
    }

    [Fact]
    public void ChangedIdentityIsPreservedByDeleteBinding()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "source.json");
        File.WriteAllText(path, "original");
        string identity;
        string digest;
        using (PackageBrokerPolicyActions.PinnedPath source = PinFile(path, WinAPI.GENERIC_READ))
        {
            identity = PackageBrokerPolicyActions.FileIdentity(source.Leaf);
            digest = PackageBrokerPolicyActions.FileContentDigest(source.Leaf);
        }

        File.Delete(path);
        File.WriteAllText(path, "replacement");
        using PackageBrokerPolicyActions.PinnedPath replacement = PinFile(
            path,
            WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES);
        Assert.False(
            PackageBrokerPolicyActions.DeleteFileIfIdentityAndDigestMatch(
                replacement.Leaf,
                identity,
                digest));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void UnavailableDeleteHandlePreservesLegacySource()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "source.json");
        File.WriteAllText(path, "{}");
        using PackageBrokerPolicyActions.PinnedPath source = PinFile(path, WinAPI.GENERIC_READ);
        PackageBrokerPolicyActions.MigrationRecord record = new(
            PackageBrokerPolicyActions.FileIdentity(source.Leaf),
            PackageBrokerPolicyActions.FileContentDigest(source.Leaf),
            "destination",
            "digest");
        using FileStream blocker = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        string diagnostic = null;

        Assert.False(
            PackageBrokerPolicyActions.TryDeleteLegacyPolicySource(
                message => diagnostic = message,
                path,
                record));
        Assert.True(File.Exists(path));
        Assert.Contains("preserving both copies", diagnostic);
    }

    [Fact]
    public void NoReplaceMovePreservesCollisionAndCleansOnlyBoundTemporary()
    {
        using TempDirectory temp = new();
        string source = Path.Combine(temp.Path, "legacy.json");
        string temporary = Path.Combine(temp.Path, "migration.tmp");
        string destination = Path.Combine(temp.Path, "managed.json");
        File.WriteAllText(source, "legacy");
        File.WriteAllText(temporary, "migrated");
        File.WriteAllText(destination, "external");
        string temporaryIdentity;
        string temporaryDigest;
        using (PackageBrokerPolicyActions.PinnedPath pinned = PinFile(temporary, WinAPI.GENERIC_READ))
        {
            temporaryIdentity = PackageBrokerPolicyActions.FileIdentity(pinned.Leaf);
            temporaryDigest = PackageBrokerPolicyActions.FileContentDigest(pinned.Leaf);
        }

        Assert.Equal(
            PackageBrokerPolicyActions.NoReplaceMoveResult.DestinationExists,
            PackageBrokerPolicyActions.MoveFileNoReplace(temporary, destination));
        Assert.Equal("legacy", File.ReadAllText(source));
        Assert.Equal("external", File.ReadAllText(destination));

        using (PackageBrokerPolicyActions.PinnedPath pinned =
            PackageBrokerPolicyActions.PinTemporaryForCleanup(temporary, allowMissing: false))
        {
            Assert.True(
                PackageBrokerPolicyActions.DeleteFileIfIdentityAndDigestMatch(
                    pinned.Leaf,
                    temporaryIdentity,
                    temporaryDigest));
        }
        Assert.False(File.Exists(temporary));
        Assert.Equal("external", File.ReadAllText(destination));
    }

    [Fact]
    public void TemporaryCleanupHandleSupportsDigestBindingAndPreservesMutation()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "migration.tmp");
        File.WriteAllText(path, "migrated");
        string identity;
        string digest;
        using (PackageBrokerPolicyActions.PinnedPath original = PinFile(path, WinAPI.GENERIC_READ))
        {
            identity = PackageBrokerPolicyActions.FileIdentity(original.Leaf);
            digest = PackageBrokerPolicyActions.FileContentDigest(original.Leaf);
        }

        using (PackageBrokerPolicyActions.PinnedPath cleanup =
            PackageBrokerPolicyActions.PinTemporaryForCleanup(path, allowMissing: false))
        {
            Assert.True(
                PackageBrokerPolicyActions.FileIdentityAndDigestMatch(
                    cleanup.Leaf,
                    identity,
                    digest));
        }

        File.WriteAllText(path, "mutated");
        using PackageBrokerPolicyActions.PinnedPath mutated =
            PackageBrokerPolicyActions.PinTemporaryForCleanup(path, allowMissing: false);
        Assert.False(
            PackageBrokerPolicyActions.FileIdentityAndDigestMatch(
                mutated.Leaf,
                identity,
                digest));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void NoReplaceMovePublishesWhenDestinationIsMissing()
    {
        using TempDirectory temp = new();
        string temporary = Path.Combine(temp.Path, "migration.tmp");
        string destination = Path.Combine(temp.Path, "managed.json");
        File.WriteAllText(temporary, "migrated");

        Assert.Equal(
            PackageBrokerPolicyActions.NoReplaceMoveResult.Moved,
            PackageBrokerPolicyActions.MoveFileNoReplace(temporary, destination));
        Assert.False(File.Exists(temporary));
        Assert.Equal("migrated", File.ReadAllText(destination));
    }

    [Fact]
    public void NoReplaceMovePropagatesUnrelatedErrors()
    {
        using TempDirectory temp = new();
        string missing = Path.Combine(temp.Path, "missing.tmp");
        string destination = Path.Combine(temp.Path, "managed.json");

        Assert.Throws<Win32Exception>(
            () => PackageBrokerPolicyActions.MoveFileNoReplace(missing, destination));
        Assert.False(File.Exists(destination));
    }

    [Fact]
    public void SecurityDescriptorAllocationUsesCheckedLength()
    {
        Assert.Equal(256, PackageBrokerPolicyActions.AllocateSecurityDescriptorBuffer(256).Length);
        Assert.Throws<OverflowException>(
            () => PackageBrokerPolicyActions.AllocateSecurityDescriptorBuffer(uint.MaxValue));
    }

    [Fact]
    public void LegacyYamlProbeDistinguishesFileMissingAndDirectory()
    {
        using TempDirectory temp = new();
        string file = Path.Combine(temp.Path, "policy.yaml");
        string missing = Path.Combine(temp.Path, "missing.yaml");
        string directory = Directory.CreateDirectory(Path.Combine(temp.Path, "directory.yaml")).FullName;
        File.WriteAllText(file, "not read");

        Assert.True(PackageBrokerPolicyActions.TryProbePinnedOrdinaryFile(file, out string fileDiagnostic));
        Assert.Null(fileDiagnostic);
        Assert.False(PackageBrokerPolicyActions.TryProbePinnedOrdinaryFile(missing, out string missingDiagnostic));
        Assert.Null(missingDiagnostic);
        Assert.False(PackageBrokerPolicyActions.TryProbePinnedOrdinaryFile(directory, out string directoryDiagnostic));
        Assert.Contains("could not safely inspect", directoryDiagnostic);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LegacyYamlProbeRejectsJunctionWithoutFollowingTarget(bool dangling)
    {
        using TempDirectory temp = new();
        string target = Directory.CreateDirectory(Path.Combine(temp.Path, "target")).FullName;
        string sentinel = Path.Combine(target, "sentinel");
        File.WriteAllText(sentinel, "untouched");
        string link = Path.Combine(temp.Path, "policy.yaml");
        CreateDirectoryJunction(link, target);
        if (dangling)
        {
            File.Delete(sentinel);
            Directory.Delete(target);
        }

        Assert.False(PackageBrokerPolicyActions.TryProbePinnedOrdinaryFile(link, out string diagnostic));
        Assert.Contains("could not safely inspect", diagnostic);
        if (!dangling)
        {
            Assert.Equal("untouched", File.ReadAllText(sentinel));
        }
        Directory.Delete(link);
    }

    [Fact]
    public void LegacyYamlProbeRejectsRemotePathBeforeAccess()
    {
        string remote = $@"\\127.0.0.1\missing-{Guid.NewGuid():N}\policy.yaml";

        Assert.False(PackageBrokerPolicyActions.TryProbePinnedOrdinaryFile(remote, out string diagnostic));
        Assert.Contains("refusing to inspect remote", diagnostic);
    }

    [Fact]
    public void HardLinkedFileIsRejected()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "policy.json");
        string alias = Path.Combine(temp.Path, "alias.json");
        File.WriteAllText(path, "{}");
        Assert.True(CreateHardLink(alias, path, IntPtr.Zero));

        Assert.Throws<InvalidOperationException>(() =>
        {
            using PackageBrokerPolicyActions.PinnedPath _ = PinFile(path, WinAPI.FILE_READ_ATTRIBUTES);
        });
    }

    [Fact]
    public void DirectoryReparsePointIsRejectedWithoutTouchingTarget()
    {
        using TempDirectory temp = new();
        string target = Directory.CreateDirectory(Path.Combine(temp.Path, "target")).FullName;
        string link = Path.Combine(temp.Path, "link");
        CreateDirectoryJunction(link, target);

        Assert.Throws<InvalidOperationException>(() =>
        {
            using PackageBrokerPolicyActions.PinnedPath _ =
                PackageBrokerPolicyActions.PinPathWithoutReparse(
                    link,
                    leafIsDirectory: true,
                    allowMissingLeaf: false,
                    leafAccess: WinAPI.FILE_READ_ATTRIBUTES);
        });
        Assert.Empty(Directory.EnumerateFileSystemEntries(target));
        Directory.Delete(link);
    }

    private static void CreateDirectoryJunction(string link, string target)
    {
        using Process process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/d /c mklink /J \"{link}\" \"{target}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
        });
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    private static string GetSystemVolumeGuidRoot()
    {
        using Process process = Process.Start(new ProcessStartInfo
        {
            FileName = "mountvol.exe",
            Arguments = @"C:\ /L",
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        });
        string output = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        Assert.StartsWith(@"\\?\Volume{", output, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(@"\", output);
        return output;
    }

    [Fact]
    public void SecureDirectoryCreationAppliesDescriptorAtCreation()
    {
        using TempDirectory temp = new();
        string path = Path.Combine(temp.Path, "secured");
        string sid = WindowsIdentity.GetCurrent().User.Value;
        string sddl = $"O:{sid}G:{sid}D:P(A;OICI;FA;;;{sid})";

        PackageBrokerPolicyActions.CreateDirectoryWithSecurity(path, sddl);

        PackageBrokerPolicyActions.VerifySecurityDescriptor(
            new DirectoryInfo(path).GetAccessControl(),
            sddl);
    }

    [Fact]
    public void SecurityDescriptorComparisonIgnoresAuditRules()
    {
        const string expected = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        DirectorySecurity actual =
            DirectorySecurity($"{expected}S:(AU;SA;FA;;;WD)");

        PackageBrokerPolicyActions.VerifySecurityDescriptor(actual, expected);
    }

    [Theory]
    [InlineData("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)")]
    [InlineData("O:SYG:SYD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
    public void SecurityDescriptorComparisonRejectsOwnerDaclOrProtectionChanges(string actualSddl)
    {
        const string expected = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

        Assert.Throws<InvalidOperationException>(
            () => PackageBrokerPolicyActions.VerifySecurityDescriptor(
                DirectorySecurity(actualSddl),
                expected));
    }

    [Fact]
    public void MigrationActionsUseDeferredRollbackCommitSequence()
    {
        ManagedAction ensure = ActionFor(nameof(PackageBrokerPolicyActions.EnsureProgramDataPackageBrokerDirectory));
        ManagedAction rollback = ActionFor(nameof(PackageBrokerPolicyActions.RollbackLegacyPackageBrokerPolicyMigration));
        ManagedAction migrate = ActionFor(nameof(PackageBrokerPolicyActions.MigrateLegacyPackageBrokerPolicy));
        ManagedAction commit = ActionFor(nameof(PackageBrokerPolicyActions.CommitLegacyPackageBrokerPolicyMigration));

        Assert.Equal(Execute.deferred, ensure.Execute);
        Assert.Equal(Execute.rollback, rollback.Execute);
        Assert.Equal(Execute.deferred, migrate.Execute);
        Assert.Equal(Execute.commit, commit.Execute);
        Assert.False(ensure.Impersonate);
        Assert.False(rollback.Impersonate);
        Assert.False(migrate.Impersonate);
        Assert.False(commit.Impersonate);
        Assert.Equal(Return.ignore, rollback.Return);
        Assert.Equal(Return.check, ensure.Return);
        Assert.Equal(Return.check, migrate.Return);
        Assert.Equal(Return.ignore, commit.Return);
        Assert.Equal(When.Before, rollback.When);
        Assert.Equal(When.After, migrate.When);
        Assert.Equal(When.After, commit.When);
        Assert.Equal(migrate.Id, rollback.Step.ToString());
        Assert.Equal(ensure.Id, migrate.Step.ToString());
        Assert.Contains("createProgramDataDirectory", ensure.Step.ToString());
        Assert.Equal(migrate.Id, commit.Step.ToString());
        Assert.Equal(Condition.NOT_BeingRemoved.ToString(), ensure.Condition.ToString());
        Assert.Equal(Condition.NOT_BeingRemoved.ToString(), migrate.Condition.ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PolicyConsentDiscoveryIsTransactionalAndArchitectureCorrect(bool win64)
    {
        RegValue value = Program.CreatePolicyConsentRegistryValue(
            "ProtocolVersion",
            DevolutionsAgent.Resources.Includes.POLICY_CONSENT_PROTOCOL_VERSION,
            win64);

        Assert.Equal(RegistryHive.LocalMachine, value.Root);
        Assert.Equal(@"Software\Devolutions\Agent\PolicyConsentHelper", value.Key);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
        Assert.Equal(win64, value.Win64);
        Assert.Equal(
            win64 ? "Type=string; Component:Win64=yes" : "Type=string",
            value.AttributesDefinition);
        Assert.Contains(Features.AGENT_FEATURE, value.ActualFeatures);
    }

    [Theory]
    [InlineData(Platform.x86, false)]
    [InlineData(Platform.x64, true)]
    [InlineData(Platform.arm64, true)]
    public void PolicyConsentDiscoveryUsesNativeRegistryView(Platform platform, bool expected)
    {
        Assert.Equal(expected, Program.Use64BitRegistryView(platform));
    }

    [Fact]
    public void PolicyConsentDiscoveryPublishesFixedProtectedHelperIdentity()
    {
        (string Name, string Value)[] values =
        [
            ("ProtocolVersion", DevolutionsAgent.Resources.Includes.POLICY_CONSENT_PROTOCOL_VERSION),
            ("ExecutableName", DevolutionsAgent.Resources.Includes.POLICY_CONSENT_EXECUTABLE_NAME),
            ("ExecutablePath", "[INSTALLDIR]DevolutionsAgentPolicyConsent.exe"),
            ("ProductName", DevolutionsAgent.Resources.Includes.POLICY_CONSENT_PRODUCT_NAME),
        ];

        foreach ((string name, string expectedValue) in values)
        {
            RegValue value = Program.CreatePolicyConsentRegistryValue(name, expectedValue, true);
            Assert.Equal(expectedValue, value.Value);
            Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
            Assert.Contains(Features.AGENT_FEATURE, value.ActualFeatures);
        }
    }

    [Theory]
    [InlineData("marker inspection")]
    [InlineData("marker deletion")]
    [InlineData("source cleanup")]
    public void CommitCleanupFailuresRemainSuccessful(string stage)
    {
        string diagnostic = null;

        ActionResult result = PackageBrokerPolicyActions.RunBestEffortCommit(
            message => diagnostic = message,
            () => throw new IOException(stage));

        Assert.Equal(ActionResult.Success, result);
        Assert.Contains(stage, diagnostic);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void EventLogSourceUsesNativeMsiRegistryLifecycle(bool win64)
    {
        RegValue value = Program.CreateEventLogSourceRegistryValue(win64);

        Assert.Equal(RegistryHive.LocalMachine, value.Root);
        Assert.Equal(
            @"SYSTEM\CurrentControlSet\Services\EventLog\Application\Devolutions Agent",
            value.Key);
        Assert.Equal("EventMessageFile", value.Name);
        Assert.Equal("[INSTALLDIR]DevolutionsAgent.exe", value.Value);
        Assert.Equal(win64, value.Win64);
        Assert.Equal(RegistryKeyAction.createAndRemoveOnUninstall, value.RegistryKeyAction);
        Assert.False(value.ForceCreateOnInstall);
        Assert.False(value.ForceDeleteOnUninstall);
        Assert.Contains("Type=string", value.AttributesDefinition);
    }

    private static ManagedAction ActionFor(string methodName) =>
        Assert.IsAssignableFrom<ManagedAction>(
            AgentActions.Actions.Single(
                action => action is ManagedAction managed && managed.MethodName == methodName));

    private static PackageBrokerPolicyActions.PinnedPath PinFile(string path, uint access) =>
        PackageBrokerPolicyActions.PinPathWithoutReparse(
            path,
            leafIsDirectory: false,
            allowMissingLeaf: false,
            leafAccess: access);

    private static FileSecurity Security(string sddl)
    {
        RawSecurityDescriptor descriptor = new(sddl);
        byte[] binary = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binary, 0);
        FileSecurity security = new();
        security.SetSecurityDescriptorBinaryForm(binary);
        return security;
    }

    private static DirectorySecurity DirectorySecurity(string sddl)
    {
        RawSecurityDescriptor descriptor = new(sddl);
        byte[] binary = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binary, 0);
        DirectorySecurity security = new();
        security.SetSecurityDescriptorBinaryForm(binary);
        return security;
    }

    [DllImport("kernel32", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);

    private sealed class TempDirectory : IDisposable
    {
        internal TempDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"DevolutionsAgentInstallerTests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
