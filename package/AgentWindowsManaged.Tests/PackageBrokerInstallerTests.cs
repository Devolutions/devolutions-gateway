using DevolutionsAgent;
using DevolutionsAgent.Actions;
using System;
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
            WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES))
        {
            PackageBrokerPolicyActions.DeleteFileByHandle(pinned.Leaf);
        }

        Assert.False(File.Exists(path));
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
        using Process process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/d /c mklink /J \"{link}\" \"{target}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
        });
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);

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
        Assert.Equal(Return.check, commit.Return);
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
