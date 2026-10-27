using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

using DevolutionsGateway.Actions;

using Microsoft.Win32.SafeHandles;

using Xunit;
using Xunit.Abstractions;

namespace DevolutionsGateway.Installer.Tests;

public sealed class SecureDirectoryTests
{
    private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User;

    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);

    private static readonly SecurityIdentifier NetworkService = new(WellKnownSidType.NetworkServiceSid, null);

    // Owned by the current user, with a protected DACL granting full control to the current user and SYSTEM only.
    // A folder under the temporary directory inherits more entries, such as one for Administrators.
    private static readonly string ProtectedSddl = $"O:{CurrentUser}D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)";

    private static readonly string[] GatewayNames = ["Devolutions", "Gateway"];

    // Entries for files and folders, for files only, and for folders only.
    // No generic right, which the file system stores mapped where .NET stores it as it is.
    // No CREATOR OWNER entry, because Windows keeps the entry it gave a folder's owner as an explicit one when the
    // folder's parent didn't mark its DACL auto-inherited, where SetSecurityAndInheritBelow counts it as inherited,
    // which grants the same access.
    // No LOCAL SERVICE entry, which SetSecurityAndInheritBelow removes where Windows keeps it.
    private static readonly string TreeSddl =
        $"O:{CurrentUser}D:PAI(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)(A;OI;FR;;;BU)(A;CI;0x1200a9;;;AU)";

    private static readonly string[] UsersFileNames = ["Devolutions", "Gateway", "users.txt"];

    private readonly ILogger logger;

    public SecureDirectoryTests(ITestOutputHelper output) => this.logger = new OutputLogger(output);

    // oracle: spec Microsoft Learn CreateFileW §dwShareMode, FILE_SHARE_DELETE
    [Fact]
    public void HeldDirectoryCantBeRenamedUntilItsHandleIsClosed()
    {
        AssertHoldsUntilClosed(path => SecureDirectory.Hold(path));
    }

    // oracle: spec Microsoft Learn CreateFileW §dwShareMode, FILE_SHARE_DELETE
    [Fact]
    public void DirectoryOpenedToReadAndHoldCantBeRenamedUntilItsHandleIsClosed()
    {
        AssertHoldsUntilClosed(path => SecureDirectory.OpenToRead(path, hold: true));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndInheritBelowRefusesAFileAndLeavesItUnchanged()
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "data");
        File.WriteAllText(path, "");
        string before = FileSddl(path);
        using SafeFileHandle handle = SecureDirectory.HoldToSetSecurity(path);

        Assert.Throws<IOException>(
            () => SecureDirectory.SetSecurityAndInheritBelow(handle, path, ProtectedSddl, [], this.logger));

        Assert.Equal(before, FileSddl(path));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetSecurityAndInheritBelowAppliesTheOwnerAndTheProtectedDacl()
    {
        using TempFolder folder = new();
        string gateway = CreateGatewayFolder(folder.Path);

        this.SetSecurityAndInheritBelow(folder.Path, ProtectedSddl);

        AssertProtectedSecurity(new DirectoryInfo(gateway).GetAccessControl());
    }

    // The installer's templates mark the DACL auto-inherited, so that the entries created below hold what they inherit
    // as inherited entries, which a later reset tells apart from their explicit ones without the folder's earlier DACL.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CreateGivesTheNewDirectoryExactlyTheSecurityDescriptor()
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "data");

        Assert.True(SecureDirectory.Create(path, ProtectedSddl.Replace("D:P", "D:PAI")));

        AssertProtectedSecurity(new DirectoryInfo(path).GetAccessControl());
        Assert.Equal(
            ControlFlags.DiscretionaryAclAutoInherited,
            new RawSecurityDescriptor(RawSddl(path)).ControlFlags & ControlFlags.DiscretionaryAclAutoInherited);
    }

    [Theory]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("SYSTEM", "S-1-5-18", true)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Administrators", "S-1-5-32-544", true)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", true)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone", "S-1-1-0", false)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users", "S-1-5-32-545", false)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("LOCAL SERVICE", "S-1-5-19", false)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("NETWORK SERVICE", "S-1-5-20", false)]
    public void WellKnownOwnerIsTrustedOnlyWhenPrivileged(string name, string sid, bool expected)
    {
        Assert.Equal(
            (name, expected), (name, SecureDirectory.IsTrustedOwner(new SecurityIdentifier(sid), this.logger)));
    }

    // oracle: property round-trip
    [Fact]
    public void ReadSecurityReadsTheOwnerAndTheDaclThatCreateApplied()
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "data");
        Assert.True(SecureDirectory.Create(path, ProtectedSddl));

        using SafeFileHandle handle = SecureDirectory.OpenToRead(path, hold: false);
        (RawSecurityDescriptor security, bool isReparsePoint, bool isDirectory) = SecureDirectory.ReadSecurity(handle);

        // Both sides go through the same SDDL rendering, which writes some account SIDs as aliases such as LA.
        Assert.Equal(
            new RawSecurityDescriptor(ProtectedSddl).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access),
            security.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access));
        Assert.False(isReparsePoint);
        Assert.True(isDirectory);
    }

    // Windows computes what an entry inherits when a directory's DACL is passed on, and when the entry's DACL
    // protection is removed, through SetNamedSecurityInfo, which .NET calls to persist a FileSecurity or a
    // DirectorySecurity; SetSecurityAndInheritBelow must give each file and folder the DACL these calls give it,
    // without resolving any path again.
    // oracle: reference System.IO.Directory.SetAccessControl and File.SetAccessControl, then SetAccessRuleProtection(false, false) top-down, run live
    [Theory]
    [InlineData("a file directly in the folder")]
    [InlineData("a file in a subfolder", "sub")]
    [InlineData("a file two subfolders down", "sub", "deeper")]
    public void InheritBelowGivesAProtectedFileTheDaclWindowsGivesItWhenItsProtectionIsRemoved(
        string scenario, params string[] subfolders)
    {
        AssertInheritsAsWindows(scenario, subfolders, (gateway, file) => ProtectFile(file), TreeSddl);
    }

    // An administrator who protects a folder below Gateway decides who may use it, so the folder keeps its DACL, and
    // the files below it get what it passes on.
    // oracle: reference System.IO.Directory.SetAccessControl and File.SetAccessControl, then SetAccessRuleProtection(false, false) top-down on files and unprotected folders, run live
    [Theory]
    [InlineData("a folder directly in the folder", "sub")]
    [InlineData("a folder two levels down", "sub", "deeper")]
    public void InheritBelowKeepsTheDaclOfAProtectedFolderAndResetsTheFilesBelowItAgainstIt(
        string scenario, params string[] subfolders)
    {
        AssertInheritsAsWindows(
            scenario,
            subfolders,
            (gateway, file) =>
            {
                ProtectDirectory(Path.GetDirectoryName(file));
                ProtectFile(file);
            },
            TreeSddl);
    }

    // A file or folder created before the folder got its current DACL holds the entries it inherited then, such as
    // none for a service account chosen later, or one for an account that no longer has access, until its inherited
    // entries are computed again.
    // Earlier installers stored the folder's DACL without marking it auto-inherited, so the entries below hold what
    // they inherited as plain entries, which only the folder's earlier DACL tells apart from explicit ones.
    // oracle: reference System.IO.Directory.SetAccessControl and File.SetAccessControl, then SetAccessRuleProtection(false, false) top-down, run live
    [Theory]
    [InlineData("a file directly in the folder", true)]
    [InlineData("a file in a subfolder", true, "sub")]
    [InlineData("a file two subfolders down", true, "sub", "deeper")]
    [InlineData("a file directly in a folder not marked auto-inherited", false)]
    [InlineData("a file in a subfolder of a folder not marked auto-inherited", false, "sub")]
    [InlineData("a file two subfolders down a folder not marked auto-inherited", false, "sub", "deeper")]
    public void InheritBelowGivesEntriesWithStaleInheritedEntriesTheDaclWindowsGivesThem(
        string scenario, bool autoInherited, params string[] subfolders)
    {
        AssertInheritsAsWindows(
            scenario,
            subfolders,
            (gateway, file) => { },
            $"O:{CurrentUser}D:PAI(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)(A;OICI;0x1301ff;;;NS)",
            autoInherited ? TreeSddl : TreeSddl.Replace("D:PAI", "D:P"));
    }

    // An earlier installer gave Gateway a DACL that LOCAL SERVICE could write through, stored without being marked
    // auto-inherited, so a folder below holds what it inherited as plain entries.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void InheritBelowReplacesTheLocalServiceEntriesAnEarlierInstallerPassedOnByTheServiceAccount()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        string gateway = Path.Combine(folder.Path, "Devolutions", "Gateway");
        Assert.True(SecureDirectory.Create(
            gateway, $"O:{CurrentUser}D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)(A;OICI;0x1201bf;;;LS)"));
        Assert.Equal(
            (ControlFlags)0,
            new RawSecurityDescriptor(RawSddl(gateway)).ControlFlags & ControlFlags.DiscretionaryAclAutoInherited);
        string recordings = folder.CreateDirectory("Devolutions", "Gateway", "recordings");
        string file = Path.Combine(recordings, "file.txt");
        File.WriteAllText(file, "");
        // As stored, since .NET reads a DACL through GetNamedSecurityInfo, which tells inherited entries apart.
        Assert.True(
            new RawSecurityDescriptor(RawSddl(recordings)).DiscretionaryAcl
                .Cast<CommonAce>()
                .Any(ace => ace.SecurityIdentifier == LocalService && (ace.AceFlags & AceFlags.Inherited) == 0),
            "the subfolder starts with a plain entry for LOCAL SERVICE");
        Assert.True(Allows(LocalService, File.GetAccessControl(file)), "the file starts with an entry for LOCAL SERVICE");

        // The installer's template, with NETWORK SERVICE as the service account and the current user as the owner.
        this.SetSecurityAndInheritBelow(
            folder.Path,
            $"O:{CurrentUser}D:PAI(A;OICI;FA;;;SY)(A;OICI;0x1201ff;;;NS)(A;OICIIO;0x1301ff;;;NS)(A;OICI;FA;;;{CurrentUser})");

        Assert.Equal(
            (false, true, false, true),
            (Allows(LocalService, Directory.GetAccessControl(recordings)),
                Allows(NetworkService, Directory.GetAccessControl(recordings)),
                Allows(LocalService, File.GetAccessControl(file)),
                Allows(NetworkService, File.GetAccessControl(file))));
    }

    // Earlier installers gave LOCAL SERVICE write access, which a protected folder holds as explicit entries.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void InheritBelowRemovesLocalServiceFromAProtectedFolderAndAFileBelowItAndKeepsTheirOtherEntries()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        string gateway = Path.Combine(folder.Path, "Devolutions", "Gateway");
        Assert.True(SecureDirectory.Create(gateway, TreeSddl));
        string sub = folder.CreateDirectory("Devolutions", "Gateway", "sub");
        DirectorySecurity subSecurity = new();
        subSecurity.SetSecurityDescriptorSddlForm(
            $"D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;0x1301ff;;;LS)(A;OICI;FR;;;BU)", AccessControlSections.Access);
        Directory.SetAccessControl(sub, subSecurity);
        string file = Path.Combine(sub, "file.txt");
        File.WriteAllText(file, "");
        FileSecurity fileSecurity = new();
        fileSecurity.SetSecurityDescriptorSddlForm(
            $"D:P(A;;FA;;;{CurrentUser})(A;;0x1301ff;;;LS)", AccessControlSections.Access);
        File.SetAccessControl(file, fileSecurity);

        this.SetSecurityAndInheritBelow(folder.Path, TreeSddl);

        DirectorySecurity subAfter = Directory.GetAccessControl(sub);
        FileSecurity fileAfter = File.GetAccessControl(file);
        Assert.Equal(
            (true, false, true, true, false, false, true, true),
            (subAfter.AreAccessRulesProtected,
                Allows(LocalService, subAfter),
                Allows(CurrentUser, subAfter),
                Allows(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), subAfter),
                fileAfter.AreAccessRulesProtected,
                Allows(LocalService, fileAfter),
                Allows(CurrentUser, fileAfter),
                Allows(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), fileAfter)));
    }

    // Another action gives the users database a DACL that only SYSTEM, administrators and the service account can
    // read, so resetting it here first would let users read it, through what Gateway passes on, until then.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void InheritBelowLeavesAnEntryItIsToldToKeepUnchangedAndResetsTheOthers()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        string gateway = Path.Combine(folder.Path, "Devolutions", "Gateway");
        Assert.True(SecureDirectory.Create(gateway, TreeSddl));
        string users = CreateProtectedFile(Path.Combine(gateway, "users.txt"));
        string other = CreateProtectedFile(Path.Combine(gateway, "other.txt"));
        string before = FileSddl(users);

        this.SetSecurityAndInheritBelow(folder.Path, TreeSddl, "users.txt");

        Assert.Equal(
            (before, false),
            (FileSddl(users), File.GetAccessControl(other).AreAccessRulesProtected));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void InheritBelowLeavesTheFilesBehindAJunctionInsideTheFolderUnchanged()
    {
        using TempFolder folder = new();
        string gateway = CreateGatewayFolder(folder.Path);
        string outside = folder.CreateDirectory("outside");
        string target = CreateProtectedFile(Path.Combine(outside, "file.txt"));
        string before = FileSddl(target);
        TempFolder.CreateJunction(Path.Combine(gateway, "link"), outside);

        this.SetSecurityAndInheritBelow(folder.Path, ProtectedSddl);

        Assert.Equal(before, FileSddl(target));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void InheritBelowLeavesAFileWithAnotherHardLinkUnchanged()
    {
        using TempFolder folder = new();
        string gateway = CreateGatewayFolder(folder.Path);
        string outside = CreateProtectedFile(Path.Combine(folder.CreateDirectory("outside"), "file.txt"));
        string before = FileSddl(outside);
        TempFolder.CreateHardLink(Path.Combine(gateway, "link.txt"), outside);

        this.SetSecurityAndInheritBelow(folder.Path, ProtectedSddl);

        Assert.Equal(before, FileSddl(outside));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void InheritBelowRefusesAJunctionAtTheFolderAndLeavesItsTargetAndTheFilesBehindItUnchanged()
    {
        using TempFolder folder = new();
        folder.CreateDirectory("Devolutions");
        string outside = folder.CreateDirectory("outside");
        string target = CreateProtectedFile(Path.Combine(outside, "file.txt"));
        (string, string) before = (Sddl(outside), FileSddl(target));
        TempFolder.CreateJunction(Path.Combine(folder.Path, "Devolutions", "Gateway"), outside);

        Assert.Throws<IOException>(() => this.SetSecurityAndInheritBelow(folder.Path, ProtectedSddl));

        Assert.Equal(before, (Sddl(outside), FileSddl(target)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetFileSecurityAppliesTheOwnerAndTheProtectedDacl()
    {
        using TempFolder folder = new();
        CreateGatewayFolder(folder.Path);
        string path = Path.Combine(folder.Path, "Devolutions", "Gateway", "users.txt");
        File.WriteAllText(path, "");

        SecureDirectory.SetFileSecurity(folder.Path, UsersFileNames, ProtectedSddl);

        AssertProtectedSecurity(File.GetAccessControl(path));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetFileSecurityRefusesAJunctionAndLeavesItsTargetUnchanged()
    {
        using TempFolder folder = new();
        string gateway = CreateGatewayFolder(folder.Path);
        string target = folder.CreateDirectory("outside");
        string before = Sddl(target);
        TempFolder.CreateJunction(Path.Combine(gateway, "users.txt"), target);

        Assert.Throws<IOException>(() => SecureDirectory.SetFileSecurity(folder.Path, UsersFileNames, ProtectedSddl));

        Assert.Equal(before, Sddl(target));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetFileSecurityRefusesAJunctionAboveTheFileAndLeavesTheFileBehindItUnchanged()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("outside");
        string file = CreateProtectedFile(Path.Combine(target, "users.txt"));
        string before = FileSddl(file);
        folder.CreateDirectory("Devolutions");
        TempFolder.CreateJunction(Path.Combine(folder.Path, "Devolutions", "Gateway"), target);

        Assert.Throws<IOException>(() => SecureDirectory.SetFileSecurity(folder.Path, UsersFileNames, ProtectedSddl));

        Assert.Equal(before, FileSddl(file));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void SetFileSecurityRefusesAFileWithAnotherHardLinkAndLeavesItUnchanged()
    {
        using TempFolder folder = new();
        string gateway = CreateGatewayFolder(folder.Path);
        string outside = CreateProtectedFile(Path.Combine(folder.CreateDirectory("outside"), "file.txt"));
        string before = FileSddl(outside);
        TempFolder.CreateHardLink(Path.Combine(gateway, "users.txt"), outside);

        Assert.Throws<IOException>(() => SecureDirectory.SetFileSecurity(folder.Path, UsersFileNames, ProtectedSddl));

        Assert.Equal(before, FileSddl(outside));
    }

    // The installer accepts a missing users database, which only exists once the web application has a user, by
    // catching this error.
    // oracle: mutant a missing users database failing the install
    [Theory]
    [InlineData("missing file")]
    [InlineData("missing folder", "Devolutions")]
    public void SetFileSecurityReportsAMissingFileAsNotFound(string scenario, params string[] existing)
    {
        using TempFolder folder = new();
        folder.CreateDirectory(existing);

        Win32Exception e = Assert.Throws<Win32Exception>(
            () => SecureDirectory.SetFileSecurity(folder.Path, UsersFileNames, ProtectedSddl));

        Assert.True(SecureDirectory.IsNotFound(e), $"{scenario}: {e.NativeErrorCode}");
    }

    /// <summary>
    /// Asserts that <see cref="SecureDirectory.SetSecurityAndInheritBelow"/>, given <paramref name="sddl"/>, gives
    /// <c>Gateway</c>, the folders <c>Gateway\<paramref name="subfolders"/></c> and a file in the last one the DACLs
    /// that .NET gives the same entries in an identical tree when it sets the DACL of <c>Gateway</c>, which Windows
    /// passes on, then sets each folder below its own DACL again, which Windows passes on, and removes the protection
    /// of the file, from the top down.
    /// </summary>
    /// <param name="prepare">
    /// Changes each tree, given the path of <c>Gateway</c> and of the file, before the DACLs are set.
    /// </param>
    /// <param name="treeSddl">The security descriptor <c>Gateway</c> is created with.</param>
    private void AssertInheritsAsWindows(
        string scenario, string[] subfolders, Action<string, string> prepare, string sddl, string treeSddl = null)
    {
        using TempFolder folder = new();
        string actual = Path.Combine(folder.Path, "actual");
        string expected = Path.Combine(folder.Path, "expected");
        CreateTree(actual, subfolders, prepare, treeSddl ?? TreeSddl);
        CreateTree(expected, subfolders, prepare, treeSddl ?? TreeSddl);
        string[] directories = Enumerable.Range(0, subfolders.Length + 1)
            .Select(depth => Path.Combine([.. GatewayNames, .. subfolders.Take(depth)]))
            .ToArray();
        string file = Path.Combine([.. GatewayNames, .. subfolders, "file.txt"]);

        // .NET reorders the entries of a DACL it sets and splits an entry with a generic right, so both trees get the
        // DACL in the form .NET writes.
        DirectorySecurity gateway = new();
        gateway.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Owner | AccessControlSections.Access);
        string written = gateway.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);

        this.SetSecurityAndInheritBelow(actual, written);

        Directory.SetAccessControl(Path.Combine(expected, directories[0]), gateway);

        // Top-down, because SetNamedSecurityInfo computes what an entry inherits from its parent's current DACL.
        // A protected folder keeps its DACL, and an unprotected one gets what its parent now passes on.
        foreach (string directory in directories.Skip(1))
        {
            DirectorySecurity reference = Directory.GetAccessControl(Path.Combine(expected, directory));
            Directory.SetAccessControl(Path.Combine(expected, directory), reference);
        }

        FileSecurity fileReference = File.GetAccessControl(Path.Combine(expected, file));
        fileReference.SetAccessRuleProtection(false, false);
        File.SetAccessControl(Path.Combine(expected, file), fileReference);

        string[] Sddls(string root) =>
        [
            .. directories.Select(directory => DirectorySddl(Path.Combine(root, directory))),
            FileSddl(Path.Combine(root, file)),
        ];

        Assert.True(
            Sddls(expected).SequenceEqual(Sddls(actual)),
            $"{scenario}: {string.Join(" ", Sddls(expected))} {string.Join(" ", Sddls(actual))}");
    }

    /// <summary>
    /// Calls <see cref="SecureDirectory.SetSecurityAndInheritBelow"/> on <c>Devolutions\Gateway</c> under
    /// <paramref name="root"/>, opened as the installer opens it, keeping the entries named <paramref name="kept"/>.
    /// </summary>
    private void SetSecurityAndInheritBelow(string root, string sddl, params string[] kept)
    {
        string gateway = Path.Combine(root, "Devolutions", "Gateway");
        using SafeFileHandle handle = SecureDirectory.HoldToSetSecurity(gateway);
        SecureDirectory.SetSecurityAndInheritBelow(handle, gateway, sddl, kept, this.logger);
    }

    /// <summary>
    /// Creates <c>Devolutions\Gateway\<paramref name="subfolders"/></c> under <paramref name="root"/>, with the security
    /// descriptor <paramref name="sddl"/> on <c>Gateway</c>, and a file in the last folder, then calls
    /// <paramref name="prepare"/> with the paths of <c>Gateway</c> and of the file.
    /// </summary>
    /// <returns>The path of the file.</returns>
    private static string CreateTree(string root, string[] subfolders, Action<string, string> prepare, string sddl)
    {
        Directory.CreateDirectory(Path.Combine(root, "Devolutions"));
        string gateway = Path.Combine(root, "Devolutions", "Gateway");
        Assert.True(SecureDirectory.Create(gateway, sddl));
        string path = gateway;

        foreach (string subfolder in subfolders)
        {
            path = Path.Combine(path, subfolder);
            Directory.CreateDirectory(path);
        }

        string file = Path.Combine(path, "file.txt");
        File.WriteAllText(file, "");
        prepare(gateway, file);

        return file;
    }

    /// <summary>
    /// Creates <c>Devolutions\Gateway</c> under <paramref name="root"/>, inheriting the temporary directory's DACL.
    /// </summary>
    private static string CreateGatewayFolder(string root) =>
        Directory.CreateDirectory(Path.Combine(root, "Devolutions", "Gateway")).FullName;

    /// <summary>
    /// Creates the file <paramref name="path"/> with a protected DACL that grants full control to the current user and
    /// read access to Users.
    /// </summary>
    private static string CreateProtectedFile(string path)
    {
        File.WriteAllText(path, "");
        ProtectFile(path);
        return path;
    }

    /// <summary>
    /// Gives the file <paramref name="path"/> a protected DACL that grants full control to the current user and read
    /// access to Users.
    /// </summary>
    private static void ProtectFile(string path)
    {
        FileSecurity security = new();
        security.SetSecurityDescriptorSddlForm($"D:P(A;;FA;;;{CurrentUser})(A;;FR;;;BU)", AccessControlSections.Access);
        File.SetAccessControl(path, security);
        Assert.True(File.GetAccessControl(path).AreAccessRulesProtected);
    }

    /// <summary>
    /// Gives the directory <paramref name="path"/> a protected DACL that grants full control to the current user and
    /// read access to Users.
    /// </summary>
    private static void ProtectDirectory(string path)
    {
        DirectorySecurity security = new();
        security.SetSecurityDescriptorSddlForm(
            $"D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;FR;;;BU)",
            AccessControlSections.Access);
        Directory.SetAccessControl(path, security);
        Assert.True(Directory.GetAccessControl(path).AreAccessRulesProtected);
    }

    /// <summary>
    /// Whether an allow entry of <paramref name="security"/> names <paramref name="account"/>.
    /// </summary>
    private static bool Allows(SecurityIdentifier account, FileSystemSecurity security) =>
        security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Any(rule => rule.IdentityReference.Equals(account) && rule.AccessControlType == AccessControlType.Allow);

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
    /// Asserts that <paramref name="security"/> has exactly the owner and the protected DACL of
    /// <see cref="ProtectedSddl"/>, with no inherited entry.
    /// </summary>
    private static void AssertProtectedSecurity(FileSystemSecurity security)
    {
        Assert.Equal(CurrentUser, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(security.AreAccessRulesProtected);

        string[] rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(r => $"{r.IdentityReference} {r.AccessControlType} {r.FileSystemRights} inherited={r.IsInherited}")
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToArray();
        string[] expected = new[] { CurrentUser, LocalSystem }
            .Select(sid => $"{sid} Allow FullControl inherited=False")
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
    /// The owner, group and DACL of the file <paramref name="path"/>, with the DACL's control flags.
    /// </summary>
    private static string FileSddl(string path) =>
        File.GetAccessControl(path)
            .GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);

    /// <summary>
    /// The owner, group and DACL of the directory <paramref name="path"/>, with the DACL's control flags.
    /// </summary>
    private static string DirectorySddl(string path) =>
        Directory.GetAccessControl(path)
            .GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);

    /// <summary>
    /// The owner and DACL of the directory <paramref name="path"/> as stored, without the canonical ordering that
    /// <see cref="DirectorySecurity"/> applies when it reads them.
    /// </summary>
    private static string RawSddl(string path)
    {
        using SafeFileHandle handle = SecureDirectory.OpenToRead(path, hold: false);
        return SecureDirectory.ReadSecurity(handle).Security
            .GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
    }
}
