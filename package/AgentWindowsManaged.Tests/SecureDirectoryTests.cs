using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

using DevolutionsAgent.Actions;

using Microsoft.Win32.SafeHandles;

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
        TempFolder.CreateJunction(Path.Combine(pending, "link"), outside);

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
        TempFolder.CreateJunction(identity, outside);

        SecureDirectory.DeleteTree(folder.Path, IdentityNames, this.logger);

        Assert.False(Directory.Exists(identity));
        Assert.True(File.Exists(Path.Combine(outside, "file.txt")));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void DeleteTreeDeletesNothingThroughAJunctionAboveThePath()
    {
        using TempFolder folder = new();
        string outside = folder.CreateDirectory("outside");
        string outsideIdentity = folder.CreateDirectory("outside", "identity");
        File.WriteAllText(Path.Combine(outsideIdentity, "file.txt"), "kept");
        folder.CreateDirectory("Devolutions");
        TempFolder.CreateJunction(Path.Combine(folder.Path, "Devolutions", "Agent"), outside);

        SecureDirectory.DeleteTree(folder.Path, IdentityNames, this.logger);

        Assert.True(File.Exists(Path.Combine(outsideIdentity, "file.txt")));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityRefusesAJunctionAndLeavesItsTargetUnchanged()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("target");
        string before = Sddl(target);
        string link = Path.Combine(folder.Path, "link");
        TempFolder.CreateJunction(link, target);

        Assert.Throws<IOException>(() => SecureDirectory.SetSecurity(link, ProtectedSddl));

        Assert.Equal(before, Sddl(target));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAppliesTheOwnerAndTheProtectedDacl()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("data");

        SecureDirectory.SetSecurity(path, ProtectedSddl);

        AssertProtectedSecurity(path);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
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

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CreateGivesTheNewDirectoryExactlyTheSecurityDescriptor()
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "data");

        Assert.True(SecureDirectory.Create(path, ProtectedSddl));

        AssertProtectedSecurity(path);
    }

    [Theory]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [InlineData("SYSTEM", "S-1-5-18", true)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [InlineData("Administrators", "S-1-5-32-544", true)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [InlineData("TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", true)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone", "S-1-1-0", false)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [InlineData("Users", "S-1-5-32-545", false)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [InlineData("LOCAL SERVICE", "S-1-5-19", false)]
    public void OwnerIsTrustedOnlyWhenPrivileged(string name, string sid, bool expected)
    {
        Assert.True(expected == SecureDirectory.IsTrustedOwner(new SecurityIdentifier(sid)), name);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void ReadSecurityReadsTheOwnerAndTheDaclThatSetSecurityApplied()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("data");
        SecureDirectory.SetSecurity(path, ProtectedSddl);

        using SafeFileHandle handle = SecureDirectory.OpenToRead(path, hold: false);
        (RawSecurityDescriptor security, bool isReparsePoint) = SecureDirectory.ReadSecurity(handle);

        Assert.Equal(ProtectedSddl, security.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access));
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
}
