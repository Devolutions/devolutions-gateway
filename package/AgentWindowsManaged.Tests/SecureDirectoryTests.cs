using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

using DevolutionsAgent.Actions;
using DevolutionsAgent.Resources;

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

    // The shape earlier installers gave Agent, with write access for LOCAL SERVICE.
    // The current user stands in for SYSTEM as the owner, which a test without elevation can't set, and for
    // Administrators, whose entry a token without elevation doesn't use.
    private static readonly string LegacyAgentSddl =
        $"O:{CurrentUser}D:PAI(A;OICI;FA;;;SY)(A;OICI;0x1201bf;;;LS)(A;OICI;FA;;;{CurrentUser})(A;OICI;0x1200a9;;;BU)";

    // The installer's security descriptor for Agent, with the current user standing in as for LegacyAgentSddl.
    private static readonly string AgentSddl = Includes.PROGRAM_DATA_SDDL
        .Replace("O:SY", $"O:{CurrentUser}")
        .Replace(";;;BA)", $";;;{CurrentUser})");

    // A DACL that grants LOCAL SERVICE write access on its own.
    private static readonly string LocalServiceSddl = $"D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;0x1301ff;;;LS)";

    private static readonly string[] AgentNames = ["Devolutions", "Agent"];

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

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void DeleteTreeKeepsGoingAfterAFailureAndKeepsOnlyWhatItCouldntDelete()
    {
        using TempFolder folder = new();
        string identity = folder.CreateDirectory(IdentityNames);
        string pending = folder.CreateDirectory([.. IdentityNames, "pending"]);
        string held = Path.Combine(pending, "held.dat");
        File.WriteAllText(held, "kept");
        File.WriteAllText(Path.Combine(pending, "sibling.dat"), "deleted");
        File.WriteAllText(Path.Combine(identity, "other.dat"), "deleted");

        // Opened without delete sharing, the file can't be deleted while the stream is open.
        using (new FileStream(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            SecureDirectory.DeleteTree(folder.Path, IdentityNames, this.logger);
        }

        Assert.Equal([held], Directory.GetFileSystemEntries(identity, "*", SearchOption.AllDirectories)
            .Where(File.Exists)
            .ToArray());
        Assert.Equal([pending], Directory.GetDirectories(identity));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void HeldDirectoryCantBeRenamedUntilItsHandleIsClosed()
    {
        AssertHoldsUntilClosed(path => SecureDirectory.Hold(path));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void DirectoryOpenedToReadAndHoldCantBeRenamedUntilItsHandleIsClosed()
    {
        AssertHoldsUntilClosed(path => SecureDirectory.OpenToRead(path, hold: true));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityRefusesAJunctionAndLeavesItsTargetUnchanged()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("target");
        string before = Sddl(target);
        TempFolder.CreateJunction(Path.Combine(folder.Path, "link"), target);

        Assert.Throws<IOException>(() => SecureDirectory.SetSecurity(folder.Path, ["link"], ProtectedSddl));

        Assert.Equal(before, Sddl(target));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityRefusesAJunctionAboveTheFolderAndLeavesTheFolderBelowItsTargetUnchanged()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("target");
        string below = folder.CreateDirectory("target", "data");
        string before = Sddl(below);
        TempFolder.CreateJunction(Path.Combine(folder.Path, "link"), target);

        Assert.Throws<IOException>(() => SecureDirectory.SetSecurity(folder.Path, ["link", "data"], ProtectedSddl));

        Assert.Equal(before, Sddl(below));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityRefusesAFileAndLeavesItUnchanged()
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "data");
        File.WriteAllText(path, "");
        string before = File.GetAccessControl(path).GetSecurityDescriptorSddlForm(AccessControlSections.All);

        Assert.Throws<IOException>(() => SecureDirectory.SetSecurity(folder.Path, ["data"], ProtectedSddl));

        Assert.Equal(before, File.GetAccessControl(path).GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAppliesTheOwnerAndTheProtectedDacl()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("parent", "data");

        SecureDirectory.SetSecurity(folder.Path, ["parent", "data"], ProtectedSddl);

        AssertProtectedSecurity(path);
    }

    // The agent requires its directories to have exactly the DACL it provisions, so propagated entries would make it
    // refuse them.
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    [Fact]
    public void SetSecurityLeavesExistingChildrenUnchanged()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("data");
        string child = folder.CreateDirectory("data", "child");
        string before = RawSddl(child);

        SecureDirectory.SetSecurity(folder.Path, ["data"], ProtectedSddl);

        Assert.Equal(before, RawSddl(child));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowAppliesTheOwnerAndTheProtectedDacl()
    {
        using TempFolder folder = new();
        string agent = folder.CreateDirectory(AgentNames);

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, ProtectedSddl);

        AssertProtectedSecurity(agent);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRefusesAFileAndLeavesItUnchanged()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        string path = CreateFile(folder.Path, [.. AgentNames]);
        string before = RawSddl(path);

        Assert.Throws<IOException>(() => this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, ProtectedSddl));

        Assert.Equal(before, RawSddl(path));
    }

    // Earlier installers gave Agent write access for LOCAL SERVICE, which the entries created below it inherited.
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRemovesWhatAnEarlierAgentFolderPassedOnAndKeepsTheRest()
    {
        using TempFolder folder = new();
        CreateLegacyAgentFolder(folder.Path);
        folder.CreateDirectory([.. AgentNames, "sub", "deeper"]);
        string[] entries =
        [
            CreateFile(folder.Path, [.. AgentNames, "file.txt"]),
            Path.Combine([folder.Path, .. AgentNames, "sub"]),
            CreateFile(folder.Path, [.. AgentNames, "sub", "file.txt"]),
            Path.Combine([folder.Path, .. AgentNames, "sub", "deeper"]),
            CreateFile(folder.Path, [.. AgentNames, "sub", "deeper", "file.txt"]),
        ];
        string[] before = entries.Select(RawSddl).ToArray();
        Assert.All(before, sddl => Assert.Matches(@"D:AI\(.*\(A;(OICI)?ID;0x1201bf;;;LS\)", sddl));

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(before.Select(WithoutLocalService).ToArray(), entries.Select(RawSddl).ToArray());
    }

    // The agent may hold its files open while an install, an upgrade or a repair runs.
    // oracle: mutant the first open asks for a right that takes part in sharing checks
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRemovesLocalServiceFromAFileOpenWithoutSharing()
    {
        using TempFolder folder = new();
        CreateLegacyAgentFolder(folder.Path);
        string file = CreateFile(folder.Path, [.. AgentNames, "file.txt"]);
        string before = RawSddl(file);
        Assert.Contains(";;;LS)", before);

        using (new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);
        }

        Assert.Equal(WithoutLocalService(before), RawSddl(file));
    }

    // A protected folder, or a file below it, holds LOCAL SERVICE as an entry of its own.
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRemovesLocalServiceFromAProtectedFolderAndAFileBelowIt()
    {
        using TempFolder folder = new();
        CreateLegacyAgentFolder(folder.Path);
        string sub = folder.CreateDirectory([.. AgentNames, "sub"]);
        SetDacl(new DirectoryInfo(sub), $"D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;0x1301ff;;;LS)(A;OICI;FR;;;BU)");
        string file = CreateFile(folder.Path, [.. AgentNames, "sub", "file.txt"]);
        string[] before = [RawSddl(sub), RawSddl(file)];
        Assert.All(before, sddl => Assert.Contains(";;;LS)", sddl));

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(before.Select(WithoutLocalService).ToArray(), new[] { RawSddl(sub), RawSddl(file) });
    }

    // An entry created in a folder whose DACL isn't marked auto-inherited holds what it inherited as entries of its own.
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRemovesLocalServiceFromADaclNotMarkedAutoInherited()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        Assert.True(SecureDirectory.Create(Path.Combine([folder.Path, .. AgentNames]), LegacyAgentSddl));
        string sub = folder.CreateDirectory([.. AgentNames, "sub"]);
        string file = CreateFile(folder.Path, [.. AgentNames, "sub", "file.txt"]);
        string[] before = [RawSddl(sub), RawSddl(file)];
        Assert.All(before, sddl => Assert.Matches(@"D:\(.*\(A;(OICI)?;0x1201bf;;;LS\)", sddl));

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(before.Select(WithoutLocalService).ToArray(), new[] { RawSddl(sub), RawSddl(file) });
    }

    // The agent refuses its identity folders and files unless they keep exactly the DACL it provisions.
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowLeavesAProtectedFolderAndFileWithoutLocalServiceUnchanged()
    {
        using TempFolder folder = new();
        CreateLegacyAgentFolder(folder.Path);
        string identity = folder.CreateDirectory([.. AgentNames, "identity"]);
        SetDacl(new DirectoryInfo(identity), $"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{CurrentUser})");
        string file = CreateFile(folder.Path, [.. AgentNames, "identity", "identity.json"]);
        SetDacl(new FileInfo(file), $"D:P(A;;FA;;;SY)(A;;FA;;;{CurrentUser})");
        byte[][] before = [RawDescriptor(identity), RawDescriptor(file)];

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(before, new[] { RawDescriptor(identity), RawDescriptor(file) });
    }

    // Write access on a junction lets an account retarget or remove it, which would redirect what the agent writes
    // through it, so the junction itself loses LOCAL SERVICE, but what it points to is never reached.
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRemovesLocalServiceFromAJunctionInsideTheFolderButNotFromItsTarget()
    {
        using TempFolder folder = new();
        string agent = CreateLegacyAgentFolder(folder.Path);
        string outside = CreateOutsideFolder(folder);
        string file = Path.Combine(outside, "file.txt");
        string link = Path.Combine(agent, "link");
        TempFolder.CreateJunction(link, outside);
        string linkBefore = RawSddl(link);
        byte[][] targetBefore = [RawDescriptor(outside), RawDescriptor(file)];
        Assert.Contains(";;;LS)", linkBefore);
        Assert.All(new[] { RawSddl(outside), RawSddl(file) }, sddl => Assert.Contains(";;;LS)", sddl));

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(WithoutLocalService(linkBefore), RawSddl(link));
        Assert.Equal(targetBefore, new[] { RawDescriptor(outside), RawDescriptor(file) });
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowLeavesAFileWithAnotherHardLinkUnchanged()
    {
        using TempFolder folder = new();
        string agent = CreateLegacyAgentFolder(folder.Path);
        string outside = Path.Combine(CreateOutsideFolder(folder), "file.txt");
        TempFolder.CreateHardLink(Path.Combine(agent, "link.txt"), outside);
        string before = RawSddl(outside);
        Assert.Contains(";;;LS)", before);

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(before, RawSddl(outside));
    }

    // A name ending in a dot is listed as it is, but the Win32 path the listing gives drops the dot, so the entry can't be
    // found by that path, as an entry deleted after the listing can't.
    // oracle: mutant an entry that can't be opened by its listed name fails the walk
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowSkipsAnEntryItCantFindByItsListedNameAndGoesOn()
    {
        using TempFolder folder = new();
        string agent = CreateLegacyAgentFolder(folder.Path);
        string unreachable = Path.Combine(agent, "name.");
        TempFolder.CreateVerbatimDirectory(unreachable);
        string file = CreateFile(agent, "file.txt");
        string before = RawSddl(file);
        Assert.Contains(unreachable, Directory.GetFileSystemEntries(agent));
        Assert.False(Directory.Exists(unreachable));

        this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl);

        Assert.Equal(WithoutLocalService(before), RawSddl(file));
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndRemoveLocalServiceBelowRefusesAJunctionAtTheFolderAndLeavesWhatItPointsToUnchanged()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        string outside = CreateOutsideFolder(folder);
        string file = Path.Combine(outside, "file.txt");
        string[] before = [RawSddl(outside), RawSddl(file)];
        TempFolder.CreateJunction(Path.Combine([folder.Path, .. AgentNames]), outside);

        Assert.Throws<IOException>(() => this.SetSecurityAndRemoveLocalServiceBelow(folder.Path, AgentSddl));

        Assert.Equal(before, new[] { RawSddl(outside), RawSddl(file) });
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

    // oracle: property round-trip
    [Fact]
    public void ReadSecurityReadsTheOwnerAndTheDaclThatSetSecurityApplied()
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("data");
        SecureDirectory.SetSecurity(folder.Path, ["data"], ProtectedSddl);

        using SafeFileHandle handle = SecureDirectory.OpenToRead(path, hold: false);
        (RawSecurityDescriptor security, bool isReparsePoint, bool isDirectory) = SecureDirectory.ReadSecurity(handle);

        // Both sides go through the same SDDL rendering, which writes some account SIDs as aliases such as LA.
        Assert.Equal(
            new RawSecurityDescriptor(ProtectedSddl).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access),
            security.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access));
        Assert.False(isReparsePoint);
        Assert.True(isDirectory);
    }

    /// <summary>
    /// Calls <see cref="SecureDirectory.SetSecurityAndRemoveLocalServiceBelow"/> on <c>Devolutions\Agent</c> under
    /// <paramref name="root"/>, opened as the installer opens it.
    /// </summary>
    private void SetSecurityAndRemoveLocalServiceBelow(string root, string sddl)
    {
        string agent = Path.Combine([root, .. AgentNames]);
        using SafeFileHandle handle = SecureDirectory.HoldToSetSecurity(agent);
        SecureDirectory.SetSecurityAndRemoveLocalServiceBelow(handle, agent, sddl, this.logger);
    }

    /// <summary>
    /// Creates <c>Devolutions\Agent</c> under <paramref name="root"/> with <see cref="LegacyAgentSddl"/>, set as .NET sets
    /// it, so that the DACL is marked auto-inherited and the entries created below it hold what they inherit as inherited
    /// entries.
    /// </summary>
    private static string CreateLegacyAgentFolder(string root)
    {
        DirectoryInfo agent = Directory.CreateDirectory(Path.Combine([root, .. AgentNames]));
        DirectorySecurity security = new();
        security.SetSecurityDescriptorSddlForm(LegacyAgentSddl, AccessControlSections.Owner | AccessControlSections.Access);
        agent.SetAccessControl(security);
        return agent.FullName;
    }

    /// <summary>
    /// Creates the folder <c>outside</c> in <paramref name="folder"/> with <see cref="LocalServiceSddl"/>, and the file
    /// <c>file.txt</c> in it, which inherits that DACL.
    /// </summary>
    private static string CreateOutsideFolder(TempFolder folder)
    {
        string outside = folder.CreateDirectory("outside");
        SetDacl(new DirectoryInfo(outside), LocalServiceSddl);
        CreateFile(outside, "file.txt");
        return outside;
    }

    /// <summary>
    /// Creates the empty file <c><paramref name="root"/>\<paramref name="names"/></c>.
    /// </summary>
    private static string CreateFile(string root, params string[] names)
    {
        string path = Path.Combine([root, .. names]);
        File.WriteAllText(path, "");
        return path;
    }

    /// <summary>
    /// Sets the DACL of <paramref name="entry"/> to that of <paramref name="sddl"/>, as .NET sets it.
    /// </summary>
    private static void SetDacl(FileSystemInfo entry, string sddl)
    {
        switch (entry)
        {
            case DirectoryInfo directory:
                DirectorySecurity directorySecurity = new();
                directorySecurity.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
                directory.SetAccessControl(directorySecurity);
                break;
            case FileInfo file:
                FileSecurity fileSecurity = new();
                fileSecurity.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
                file.SetAccessControl(fileSecurity);
                break;
        }
    }

    /// <summary>
    /// <paramref name="sddl"/> without its allow entries for LOCAL SERVICE.
    /// </summary>
    private static string WithoutLocalService(string sddl) => Regex.Replace(sddl, @"\(A;[A-Z]*;[^;]*;;;LS\)", "");

    /// <summary>
    /// Asserts that a directory <paramref name="hold"/> opens can't be renamed while the handle is open, and can once it
    /// is closed.
    /// </summary>
    private static void AssertHoldsUntilClosed(Func<string, SafeFileHandle> hold)
    {
        using TempFolder folder = new();
        string path = folder.CreateDirectory("held");
        string renamed = Path.Combine(folder.Path, "renamed");

        using (hold(path))
        {
            Assert.Throws<IOException>(() => Directory.Move(path, renamed));
            Assert.True(Directory.Exists(path));
        }

        Directory.Move(path, renamed);
        Assert.True(Directory.Exists(renamed));
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
    /// The owner and DACL of the entry <paramref name="path"/> names, a link itself rather than its target, as stored,
    /// without the canonical ordering that <see cref="DirectorySecurity"/> applies when it reads them.
    /// </summary>
    private static string RawSddl(string path) =>
        RawSecurity(path).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access);

    /// <summary>
    /// The owner and DACL of the entry <paramref name="path"/> names, a link itself rather than its target, as stored, in
    /// binary form.
    /// </summary>
    private static byte[] RawDescriptor(string path)
    {
        RawSecurityDescriptor security = RawSecurity(path);
        byte[] binary = new byte[security.BinaryLength];
        security.GetBinaryForm(binary, 0);
        return binary;
    }

    private static RawSecurityDescriptor RawSecurity(string path)
    {
        using SafeFileHandle handle = SecureDirectory.OpenToRead(path, hold: false);
        return SecureDirectory.ReadSecurity(handle).Security;
    }
}
