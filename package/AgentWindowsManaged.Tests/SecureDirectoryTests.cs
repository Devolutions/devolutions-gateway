using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

using DevolutionsAgent.Actions;

using Xunit;
using Xunit.Abstractions;

namespace DevolutionsAgent.Installer.Tests;

public sealed class SecureDirectoryTests
{
    private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User;

    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    // Owned by the current user, with a protected DACL granting full control to the current user and SYSTEM only.
    // A folder under the temporary directory inherits more entries, such as one for Administrators.
    private static readonly string ProtectedSddl = $"O:{CurrentUser}D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)";

    private static readonly string[] IdentityNames = ["Devolutions", "Agent", "identity"];

    private readonly ILogger logger;

    public SecureDirectoryTests(ITestOutputHelper output) => this.logger = new OutputLogger(output);

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void DeleteTreeKeepsWhatAJunctionInsideTheTreePointsTo()
    {
        using TempFolder folder = new();
        string outside = folder.CreateDirectory("outside");
        File.WriteAllText(Path.Combine(outside, "file.txt"), "kept");
        string identity = folder.CreateDirectory(IdentityNames);
        string pending = Directory.CreateDirectory(Path.Combine(identity, "pending")).FullName;
        File.WriteAllText(Path.Combine(pending, "token.dat"), "deleted");
        CreateJunction(Path.Combine(pending, "link"), outside);

        SecureDirectory.DeleteTree(folder.Path, IdentityNames, this.logger);

        Assert.False(Directory.Exists(identity));
        Assert.True(File.Exists(Path.Combine(outside, "file.txt")));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void DeleteTreeDeletesAJunctionAtThePathButNotItsTarget()
    {
        using TempFolder folder = new();
        string outside = folder.CreateDirectory("outside");
        File.WriteAllText(Path.Combine(outside, "file.txt"), "kept");
        folder.CreateDirectory("Devolutions", "Agent");
        string identity = Path.Combine(folder.Path, "Devolutions", "Agent", "identity");
        CreateJunction(identity, outside);

        SecureDirectory.DeleteTree(folder.Path, IdentityNames, this.logger);

        Assert.False(Directory.Exists(identity));
        Assert.True(File.Exists(Path.Combine(outside, "file.txt")));
    }

    // oracle: mutant the deletion follows a junction at the data directory into its target
    [Fact]
    public void DeleteTreeDeletesNothingThroughAJunctionAboveThePath()
    {
        using TempFolder folder = new();
        string outside = folder.CreateDirectory("outside");
        string outsideIdentity = folder.CreateDirectory("outside", "identity");
        File.WriteAllText(Path.Combine(outsideIdentity, "file.txt"), "kept");
        folder.CreateDirectory("Devolutions");
        CreateJunction(Path.Combine(folder.Path, "Devolutions", "Agent"), outside);

        SecureDirectory.DeleteTree(folder.Path, IdentityNames, this.logger);

        Assert.True(File.Exists(Path.Combine(outsideIdentity, "file.txt")));
    }

    // oracle: mutant the security is applied through a junction to its target
    [Fact]
    public void SetSecurityRefusesAJunctionAndLeavesItsTargetUnchanged()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("target");
        string before = Sddl(target);
        string link = Path.Combine(folder.Path, "link");
        CreateJunction(link, target);

        Assert.Throws<IOException>(() => SecureDirectory.SetSecurity(link, ProtectedSddl));

        Assert.Equal(before, Sddl(target));
    }

    // oracle: mutant the owner or the DACL is left out, or the DACL loses its protection
    [Fact]
    public void SetSecurityAppliesTheOwnerAndTheProtectedDacl()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("data");

        SecureDirectory.SetSecurity(path, ProtectedSddl);

        AssertProtectedSecurity(path);
    }

    // oracle: mutant inheritable entries are propagated to existing children
    [Fact]
    public void SetSecurityLeavesExistingChildrenUnchanged()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("data");
        string child = folder.CreateDirectory("data", "child");
        string before = Sddl(child);

        SecureDirectory.SetSecurity(path, ProtectedSddl);

        Assert.Equal(before, Sddl(child));
    }

    // oracle: mutant the directory is created with the DACL inherited from its parent
    [Fact]
    public void CreateGivesTheNewDirectoryExactlyTheSecurityDescriptor()
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "data");

        Assert.True(SecureDirectory.Create(path, ProtectedSddl));

        AssertProtectedSecurity(path);
    }

    [Theory]
    // oracle: reference crates/now-package-broker/src/policy_security.rs TrustedWriters::AdminOrTrustedInstaller
    [InlineData("SYSTEM", "S-1-5-18", true)]
    // oracle: reference crates/agent-identity/src/windows.rs owner_is_administrator_member
    [InlineData("Administrators", "S-1-5-32-544", true)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs TrustedWriters::AdminOrTrustedInstaller
    [InlineData("TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", true)]
    // oracle: reference crates/agent-identity/src/windows.rs owner_is_administrator_member
    [InlineData("Everyone", "S-1-1-0", false)]
    // oracle: reference crates/agent-identity/src/windows.rs owner_is_administrator_member
    [InlineData("Users", "S-1-5-32-545", false)]
    // oracle: reference crates/agent-identity/src/windows.rs owner_is_administrator_member
    [InlineData("LOCAL SERVICE", "S-1-5-19", false)]
    public void OwnerIsTrustedOnlyWhenPrivileged(string name, string sid, bool expected)
    {
        Assert.True(expected == SecureDirectory.IsTrustedOwner(new SecurityIdentifier(sid)), name);
    }

    // oracle: mutant the owner is read from the target of a junction
    [Fact]
    public void ReadOwnerReportsAJunctionItself()
    {
        using TempFolder folder = new();
        string link = Path.Combine(folder.Path, "link");
        CreateJunction(link, folder.CreateDirectory("target"));

        Assert.True(SecureDirectory.ReadOwner(link).IsReparsePoint);
    }

    // oracle: mutant the owner is not read from the directory
    [Fact]
    public void ReadOwnerReadsTheOwnerOfADirectory()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("data");
        SecureDirectory.SetSecurity(path, ProtectedSddl);

        (SecurityIdentifier owner, bool isReparsePoint) = SecureDirectory.ReadOwner(path);

        Assert.Equal(CurrentUser, owner);
        Assert.False(isReparsePoint);
    }

    /// <summary>
    /// Asserts that <paramref name="path"/> has exactly the owner and the protected DACL of <see cref="ProtectedSddl"/>,
    /// with no inherited entry.
    /// </summary>
    private static void AssertProtectedSecurity(string path)
    {
        DirectorySecurity security = new DirectoryInfo(path).GetAccessControl();

        Assert.Equal(CurrentUser, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(security.AreAccessRulesProtected);

        string[] rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(r => $"{r.IdentityReference} {r.AccessControlType} {r.FileSystemRights} {r.InheritanceFlags} {r.PropagationFlags} inherited={r.IsInherited}")
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToArray();
        string[] expected = new[] { CurrentUser, LocalSystem }
            .Select(sid => $"{sid} Allow FullControl ContainerInherit, ObjectInherit None inherited=False")
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expected, rules);
    }

    /// <summary>
    /// The owner and DACL of <paramref name="path"/>, following a link at that path.
    /// </summary>
    private static string Sddl(string path) =>
        new DirectoryInfo(path)
            .GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
            .GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);

    /// <summary>
    /// Creates a junction at <paramref name="link"/> to the directory <paramref name="target"/>, which needs no
    /// elevation.
    /// </summary>
    private static void CreateJunction(string link, string target)
    {
        ProcessStartInfo startInfo = new("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using Process process = Process.Start(startInfo);
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();

        Assert.True(process.ExitCode == 0, output);
    }

    private sealed class OutputLogger(ITestOutputHelper output) : ILogger
    {
        public void Log(string msg) => output.WriteLine(msg);

        public void Log(string format, params object[] args) => output.WriteLine(format, args);
    }

    /// <summary>
    /// A new, empty folder under the temporary directory, deleted with its content on disposal.
    /// </summary>
    private sealed class TempFolder : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"secure-directory-{Guid.NewGuid():N}");

        public TempFolder() => Directory.CreateDirectory(this.Path);

        /// <summary>
        /// Creates the directory <paramref name="names"/> below this folder, with its parents.
        /// </summary>
        public string CreateDirectory(params string[] names) =>
            Directory.CreateDirectory(System.IO.Path.Combine([this.Path, .. names])).FullName;

        public void Dispose()
        {
            // A recursive Directory.Delete fails on a junction without elevation, so junctions go first.
            RemoveJunctions(this.Path);
            Directory.Delete(this.Path, recursive: true);
        }

        private static void RemoveJunctions(string directory)
        {
            foreach (string entry in Directory.GetDirectories(directory))
            {
                if (File.GetAttributes(entry).HasFlag(FileAttributes.ReparsePoint))
                {
                    Directory.Delete(entry);
                }
                else
                {
                    RemoveJunctions(entry);
                }
            }
        }
    }
}
