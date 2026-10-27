using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

using DevolutionsGateway.Actions;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;

using Record = Microsoft.Deployment.WindowsInstaller.Record;

using WixSharp;

using Xunit;
using Xunit.Abstractions;

using static DevolutionsGateway.Installer.Tests.InstallerSession;

namespace DevolutionsGateway.Installer.Tests;

[Collection(InstallerSession.Collection)]
public sealed class DataFolderTests
{
    // Values of Evaluate's checkAccess, which only Devolutions gets.
    private const bool Devolutions = true;
    private const bool Gateway = false;

    // The DACL of a Devolutions folder that SYSTEM created in ProgramData, as read on Windows 11: inherited full control
    // for SYSTEM and Administrators, an inherit-only CREATOR OWNER entry, read access for Users, and the Users entry that
    // only adds files and subdirectories.
    private const string InheritedDacl =
        "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)";

    private const string Users = "S-1-5-32-545";

    private const string Everyone = "S-1-1-0";

    private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User;

    private static readonly string GatewaySddl = $"O:{CurrentUser}D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)";

    private static readonly string[] DataFolderActions =
    [
        nameof(CustomActions.CheckProgramDataDirectory),
        nameof(CustomActions.CreateProgramDataDirectory),
        nameof(CustomActions.SetUsersDatabaseFilePermissions),
    ];

    private readonly ILogger logger;

    public DataFolderTests(ITestOutputHelper output) => this.logger = new OutputLogger(output);

    [Theory]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("SYSTEM owns Devolutions", Devolutions, "O:SY" + InheritedDacl, "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Administrators own Devolutions", Devolutions, "O:BA" + InheritedDacl, "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users own Devolutions", Devolutions, "O:BU" + InheritedDacl, "Owner " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone owns Devolutions", Devolutions, "O:WD" + InheritedDacl, "Owner " + Everyone)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users own Gateway", Gateway, "O:BU" + InheritedDacl, "Owner " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("NETWORK SERVICE owns Gateway", Gateway, "O:NS" + InheritedDacl, "Owner S-1-5-20")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may delete Devolutions", Devolutions, "O:SYD:(A;;SD;;;BU)", "Access " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may change the DACL", Devolutions, "O:SYD:(A;;WD;;;BU)", "Access " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may take ownership", Devolutions, "O:SYD:(A;;WO;;;BU)", "Access " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may delete entries", Devolutions, "O:SYD:(A;;0x40;;;BU)", "Access " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users have generic all", Devolutions, "O:SYD:(A;;GA;;;BU)", "Access " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may delete through a conditional entry", Devolutions, "O:SYD:(XA;;SD;;;BU;(Member_of {SID(BU)}))", "Access " + Users)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("null DACL", Devolutions, "O:SYD:NO_ACCESS_CONTROL", "Access " + Everyone)]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("Users get full control of entries created below", Devolutions, "O:SYD:(A;OICIIO;FA;;;BU)", "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may only add entries", Devolutions, "O:SYD:(A;CI;DCLCRPCR;;;BU)", "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users are denied deletion", Devolutions, "O:SYD:(D;;SD;;;BU)", "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("SYSTEM has full control", Devolutions, "O:SYD:(A;OICI;FA;;;SY)", "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Administrators have full control", Devolutions, "O:SYD:(A;OICI;FA;;;BA)", "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone may delete Devolutions", Devolutions, "O:SYD:(A;;SD;;;WD)", "Access " + Everyone)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone may change the DACL", Devolutions, "O:SYD:(A;;WD;;;WD)", "Access " + Everyone)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone may take ownership", Devolutions, "O:SYD:(A;;WO;;;WD)", "Access " + Everyone)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone may delete entries", Devolutions, "O:SYD:(A;;0x40;;;WD)", "Access " + Everyone)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Everyone has generic all", Devolutions, "O:SYD:(A;;GA;;;WD)", "Access " + Everyone)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("NETWORK SERVICE has full control", Devolutions, "O:SYD:(A;OICI;FA;;;NS)", "Access S-1-5-20")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("TrustedInstaller has full control", Devolutions, "O:SYD:(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)", "none")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("no owner", Devolutions, "D:(A;;FA;;;SY)", "Unreadable")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("OWNER RIGHTS has full control", Devolutions, "O:SYD:(A;OICI;FA;;;OW)", "none")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("an AppContainer package has full control", Devolutions, "O:SYD:(A;OICI;FA;;;S-1-15-2-1)", "none")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("an AppContainer capability has full control", Devolutions, "O:SYD:(A;OICI;FA;;;S-1-15-3-1)", "none")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("Users are denied deletion through an object entry", Devolutions, "O:SYD:(OD;;SD;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", "none")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("Users may delete through an object entry", Devolutions, "O:SYD:(OA;;SD;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", "Unreadable")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("an inherit-only object entry", Devolutions, "O:SYD:(OA;CIIO;SD;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", "Unreadable")]
    // oracle: reference Devolutions/devolutions-gateway@9b8b60380f6c:crates/private-fs/src/windows/security.rs Policy::check_ancestor
    [InlineData("Users may delete through a conditional object entry", Devolutions, "O:SYD:(ZA;;SD;bf967aba-0de6-11d0-a285-00aa003049e2;;BU;(Member_of {SID(BU)}))", "Unreadable")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users have full control of Gateway", Gateway, "O:SYD:(A;OICI;FA;;;BU)", "none")]
    public void RefusalFollowsTheOwnerAndTheDacl(string scenario, bool checkAccess, string sddl, string expected)
    {
        DataFolderRefusal refusal = DataFolders.Evaluate(
            "folder", new RawSecurityDescriptor(sddl), isLink: false, isDirectory: true, checkAccess, this.logger);

        Assert.Equal((scenario, expected), (scenario, Describe(refusal)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Theory]
    [InlineData(Devolutions)]
    [InlineData(Gateway)]
    public void LinkIsRefusedWhateverItsSecurity(bool checkAccess)
    {
        DataFolderRefusal refusal = DataFolders.Evaluate(
            "folder", new RawSecurityDescriptor("O:SY" + InheritedDacl), isLink: true, isDirectory: true, checkAccess, this.logger);

        Assert.Equal("Link", Describe(refusal));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Theory]
    [InlineData(Devolutions)]
    [InlineData(Gateway)]
    public void FileIsRefusedWhateverItsSecurity(bool checkAccess)
    {
        DataFolderRefusal refusal = DataFolders.Evaluate(
            "folder", new RawSecurityDescriptor("O:SY" + InheritedDacl), isLink: false, isDirectory: false, checkAccess, this.logger);

        Assert.Equal("File", Describe(refusal));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CheckRefusesAFileAtDevolutions()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        System.IO.File.WriteAllText(devolutions, "");

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "File"), (refusal?.Folder, Describe(refusal)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CreateRefusesAFileAtDevolutionsAndLeavesIt()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        System.IO.File.WriteAllText(devolutions, "kept");

        DataFolderRefusal refusal = DataFolders.Create(folder.Path, GatewaySddl, this.logger);

        Assert.Equal((devolutions, "File", "kept"), (refusal?.Folder, Describe(refusal), System.IO.File.ReadAllText(devolutions)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CheckRefusesAJunctionAtDevolutions()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        TempFolder.CreateJunction(devolutions, folder.CreateDirectory("target"));

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "Link"), (refusal?.Folder, Describe(refusal)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CreateRefusesAJunctionAtDevolutionsAndCreatesNothingInItsTarget()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("target");
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        TempFolder.CreateJunction(devolutions, target);

        DataFolderRefusal refusal = DataFolders.Create(folder.Path, GatewaySddl, this.logger);

        Assert.Equal((devolutions, "Link"), (refusal?.Folder, Describe(refusal)));
        Assert.Empty(Directory.GetFileSystemEntries(target));
    }

    [Theory]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may delete Devolutions", "SD")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("Users may delete entries of Devolutions", "0x40")]
    public void CheckRefusesADevolutionsFolderThatUsersMayReplaceOrWhoseEntriesTheyMayReplace(string scenario, string right)
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        Assert.True(SecureDirectory.Create(devolutions, ReplaceableByUsers(right)), scenario);

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "Access " + Users), (refusal?.Folder, Describe(refusal)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CreateRefusesADevolutionsFolderThatUsersMayDeleteAndCreatesNothingInIt()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        Assert.True(SecureDirectory.Create(devolutions, ReplaceableByUsers("SD")));

        DataFolderRefusal refusal = DataFolders.Create(folder.Path, GatewaySddl, this.logger);

        Assert.Equal((devolutions, "Access " + Users), (refusal?.Folder, Describe(refusal)));
        Assert.Empty(Directory.GetFileSystemEntries(devolutions));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CheckRefusesADevolutionsFolderItCantOpenAsUnreadable()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        // Opening the folder fails with access denied, not with not-found: the current user, its owner, is granted
        // neither READ_CONTROL, as the OWNER RIGHTS entry takes away the owner's implicit one, nor FILE_TRAVERSE.
        // The user keeps the rights to list the folder, read its attributes and synchronize, which deleting it needs.
        Assert.True(SecureDirectory.Create(devolutions, $"O:{CurrentUser}D:P(A;;0;;;OW)(A;OICI;FA;;;SY)(A;;0x100081;;;{CurrentUser})"));

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "Unreadable"), (refusal?.Folder, Describe(refusal)));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CheckPassesWhenTheFoldersDontExist()
    {
        using TempFolder folder = new();

        Assert.Null(DataFolders.Check(folder.Path, this.logger));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void ErrorNamesTheFolderAndTheAccountOrItsSidWhenItHasNone()
    {
        const string Folder = @"C:\ProgramData\Devolutions";
        const string Unnamed = "S-1-5-21-1-2-3-1001";
        SecurityIdentifier users = new(Users);

        string owned = new DataFolderRefusal(Folder, DataFolderProblem.Owner, users).Message("1033");
        string replaceable = new DataFolderRefusal(Folder, DataFolderProblem.Access, new SecurityIdentifier(Unnamed)).Message("1033");

        Assert.Contains(Folder, owned);
        Assert.Contains(users.Translate(typeof(NTAccount)).Value, owned);
        Assert.Contains(Folder, replaceable);
        Assert.Contains(Unnamed, replaceable);
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void ErrorIsInTheInstallerLanguage()
    {
        DataFolderRefusal refusal = new(@"C:\ProgramData\Devolutions", DataFolderProblem.Link);
        string[] messages = new[] { "1033", "1036", "1031" }.Select(refusal.Message).ToArray();

        Assert.Equal(messages.Length, messages.Distinct().Count());
        // A language the installer doesn't have falls back to English, as the rest of the installer does.
        Assert.Equal(messages[0], refusal.Message("1053"));
    }

    // The error names a folder, whose path may hold brackets, which the installer would otherwise read as property
    // references.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void ErrorIsShownAsWritten()
    {
        const string Text = @"C:\[SECRET]\x] [y [\[]";

        string shown = WithSession(["SECRET=value"], session =>
        {
            using Record record = CustomActions.MessageRecord(Text);
            return session.FormatRecord(record);
        });

        Assert.Equal(Text, shown);
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Theory]
    [InlineData(Strings.DataFolderIsLink)]
    [InlineData(Strings.DataFolderIsFile)]
    [InlineData(Strings.DataFolderOwnedByUntrustedAccount)]
    [InlineData(Strings.DataFolderReplaceableByUntrustedAccount)]
    [InlineData(Strings.DataFolderSecurityUnreadable)]
    public void ErrorIsTranslatedWithTheEnglishPlaceholders(string id)
    {
        string english = InstallerStrings.Localize("1033", id);

        Assert.NotEqual(id, english);
        Assert.All(new[] { "1036", "1031" }, language =>
        {
            string translated = InstallerStrings.Localize(language, id);
            Assert.NotEqual(id, translated);
            Assert.NotEqual(english, translated);
            Assert.Equal(Placeholders(english), Placeholders(translated));
        });
    }

    [Theory]
    [InlineData(nameof(CustomActions.CheckProgramDataDirectory))]
    [InlineData(nameof(CustomActions.CreateProgramDataDirectory))]
    public void RefusalFailsTheRunInTheInstallerLanguage(string method)
    {
        ManagedAction action = ActionOf(method);

        // oracle: intent package/WindowsManaged/INTENT.md §Data folder
        Assert.Equal(Return.check, action.Return);
        // A deferred action reads only the properties its action data carries.
        // oracle: spec Windows Installer §Obtaining Context Information for Deferred Execution Custom Actions
        Assert.Contains("ProductLanguage=[ProductLanguage]", action.UsesProperties.Split(';'));
    }

    // The security descriptors these actions apply name the service account, and a deferred action reads only the
    // properties its action data carries.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    // oracle: spec Windows Installer §Obtaining Context Information for Deferred Execution Custom Actions
    [Theory]
    [InlineData(nameof(CustomActions.CreateProgramDataDirectory))]
    [InlineData(nameof(CustomActions.SetUsersDatabaseFilePermissions))]
    public void SecurityResetGetsTheServiceAccount(string method)
    {
        string id = GatewayProperties.serviceAccountSid.Id;

        Assert.Contains($"{id}=[{id}]", ActionOf(method).UsesProperties.Split(';'));
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Theory]
    [InlineData(nameof(CustomActions.CreateProgramDataDirectory))]
    [InlineData(nameof(CustomActions.SetUsersDatabaseFilePermissions))]
    public void FailedSecurityResetFailsTheRun(string method)
    {
        Assert.Equal(Return.check, ActionOf(method).Return);
    }

    [Theory]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("first install", true)]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("major upgrade", true, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("repair", true, "Installed=00:00:00", "REINSTALL=ALL")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("maintenance", true, "Installed=00:00:00")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("full uninstall", false, "Installed=00:00:00", "REMOVE=ALL")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("old product removed by a major upgrade", false, "Installed=00:00:00", "REMOVE=ALL", "UPGRADINGPRODUCTCODE={00000000-0000-0000-0000-000000000002}")]
    public void DataFoldersAreCheckedAndResetOnEveryRunButAFullUninstall(string scenario, bool expected, params string[] properties)
    {
        bool[] evaluated = DataFolderActions
            .Select(method => EvaluateCondition(ActionOf(method).Condition.ToString(), properties))
            .ToArray();

        Assert.True(evaluated.All(e => e == expected), $"{scenario}: {string.Join(", ", evaluated)}");
    }

    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void CheckRunsBeforeTheMajorUpgradeRemovesTheInstalledProduct()
    {
        Assert.Equal(
            (When.Before, Step.RemoveExistingProducts.ToString(), UpgradeSchedule.afterInstallInitialize),
            (GatewayActions.checkProgramDataDirectory.When,
                GatewayActions.checkProgramDataDirectory.Step.ToString(),
                Program.MajorUpgrade.Schedule));
    }

    [Theory]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("the data folder")]
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [InlineData("the users database")]
    public void OnlySystemAdministratorsAndTheServiceAccountCanChangeTheData(string template)
    {
        SecurityIdentifier service = new("S-1-5-80-1-2-3-4-5");
        RawSecurityDescriptor descriptor = new(Templates[template](service));
        // Every right that changes an entry, its content or its security, including through a generic right.
        const int changing = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

        string[] writers = descriptor.DiscretionaryAcl
            .Cast<CommonAce>()
            .Where(ace => ace.AceQualifier == AceQualifier.AccessAllowed && (ace.AccessMask & changing) != 0)
            .Select(ace => ace.SecurityIdentifier.Value)
            .Distinct()
            .OrderBy(sid => sid, StringComparer.Ordinal)
            .ToArray();
        string[] expected = new[] { "S-1-5-18", "S-1-5-32-544", service.Value }
            .OrderBy(sid => sid, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expected, writers);
    }

    // A service account that is LOCAL SERVICE gets its rights through the service account's entries.
    // oracle: mutant an entry of its own for LOCAL SERVICE, such as read access
    [Theory]
    [InlineData("the data folder")]
    [InlineData("the users database")]
    public void LocalServiceHasNoEntryOfItsOwn(string template)
    {
        RawSecurityDescriptor descriptor = new(Templates[template](new SecurityIdentifier("S-1-5-80-1-2-3-4-5")));

        Assert.DoesNotContain(
            descriptor.DiscretionaryAcl.Cast<CommonAce>(),
            ace => ace.SecurityIdentifier.Equals(new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null)));
    }

    // The service account is the current user, who can then create entries in the folder without elevation.
    // oracle: intent package/WindowsManaged/INTENT.md §Data folder
    [Fact]
    public void ServiceAccountCantDeleteTheGatewayFolderButCanDeleteWhatIsBelowIt()
    {
        using TempFolder folder = new();
        string gateway = folder.CreateDirectory("Gateway");
        DirectorySecurity security = new();
        security.SetSecurityDescriptorSddlForm(Includes.ProgramDataSddl(CurrentUser), AccessControlSections.Access);
        Directory.SetAccessControl(gateway, security);
        string file = Path.Combine(gateway, "file.txt");
        System.IO.File.WriteAllText(file, "");
        string subfolder = Directory.CreateDirectory(Path.Combine(gateway, "sub")).FullName;

        FileSystemRights onFolder = RightsOf(CurrentUser, Directory.GetAccessControl(gateway));
        FileSystemRights onFile = RightsOf(CurrentUser, System.IO.File.GetAccessControl(file));
        FileSystemRights onSubfolder = RightsOf(CurrentUser, Directory.GetAccessControl(subfolder));

        Assert.Equal(
            (false, true, true, true),
            (onFolder.HasFlag(FileSystemRights.Delete),
                onFolder.HasFlag(FileSystemRights.DeleteSubdirectoriesAndFiles),
                onFile.HasFlag(FileSystemRights.Delete),
                onSubfolder.HasFlag(FileSystemRights.Delete)));
    }

    /// <summary>
    /// A security descriptor that grants Users <paramref name="right"/> on the folder.
    /// </summary>
    /// <remarks>
    /// Protected, so that the folder inherits nothing from the temporary directory, which grants the current user full
    /// control, and owned by the current user, who can't make another account the owner without elevation.
    /// </remarks>
    private static string ReplaceableByUsers(string right) =>
        $"O:{CurrentUser}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;{right};;;BU)";

    /// <summary>
    /// The problem and the account <paramref name="refusal"/> names, or <c>none</c>.
    /// </summary>
    private static string Describe(DataFolderRefusal refusal) =>
        refusal is null ? "none" : $"{refusal.Problem} {refusal.Account}".TrimEnd();

    private static readonly Dictionary<string, Func<SecurityIdentifier, string>> Templates = new()
    {
        ["the data folder"] = Includes.ProgramDataSddl,
        ["the users database"] = Includes.UsersFileSddl,
    };

    /// <summary>
    /// The rights the allow entries of <paramref name="security"/> grant <paramref name="account"/> on the object itself.
    /// </summary>
    private static FileSystemRights RightsOf(SecurityIdentifier account, FileSystemSecurity security) =>
        security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule => rule.IdentityReference.Equals(account)
                && rule.AccessControlType == AccessControlType.Allow
                && !rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
            .Aggregate((FileSystemRights)0, (rights, rule) => rights | rule.FileSystemRights);

    private static string[] Placeholders(string text) =>
        Regex.Matches(text, @"\{\d+\}").Cast<Match>().Select(m => m.Value).OrderBy(p => p).ToArray();
}
