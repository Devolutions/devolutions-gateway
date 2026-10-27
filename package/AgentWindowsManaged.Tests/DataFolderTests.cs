using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

using DevolutionsAgent.Actions;
using DevolutionsAgent.Resources;

using WixSharp;

using Xunit;
using Xunit.Abstractions;

using static DevolutionsAgent.Installer.Tests.InstallerSession;

namespace DevolutionsAgent.Installer.Tests;

[Collection(InstallerSession.Collection)]
public sealed class DataFolderTests
{
    // Values of Evaluate's checkAccess, which only Devolutions gets.
    private const bool Devolutions = true;
    private const bool Agent = false;

    // The DACL of a Devolutions folder that SYSTEM created in ProgramData, as read on Windows 11: inherited full control
    // for SYSTEM and Administrators, an inherit-only CREATOR OWNER entry, read access for Users, and the Users entry that
    // only adds files and subdirectories.
    private const string InheritedDacl =
        "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)";

    private const string Users = "S-1-5-32-545";

    private const string Everyone = "S-1-1-0";

    private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User;

    // Protected, so that the folder inherits nothing from the temporary directory, which grants the current user full
    // control, and owned by the current user, who can't make another account the owner without elevation.
    private static readonly string ReplaceableByUsersSddl =
        $"O:{CurrentUser}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;SD;;;BU)";

    private static readonly string AgentSddl = $"O:{CurrentUser}D:P(A;OICI;FA;;;{CurrentUser})(A;OICI;FA;;;SY)";

    private static readonly string[] DataFolderActions =
    [
        nameof(CustomActions.CheckProgramDataDirectory),
        nameof(CustomActions.CreateProgramDataDirectory),
    ];

    private readonly ILogger logger;

    public DataFolderTests(ITestOutputHelper output) => this.logger = new OutputLogger(output);

    [Theory]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("SYSTEM owns Devolutions", Devolutions, "O:SY" + InheritedDacl, "none")]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Administrators own Devolutions", Devolutions, "O:BA" + InheritedDacl, "none")]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users own Devolutions", Devolutions, "O:BU" + InheritedDacl, "Owner " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Everyone owns Devolutions", Devolutions, "O:WD" + InheritedDacl, "Owner " + Everyone)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users own Agent", Agent, "O:BU" + InheritedDacl, "Owner " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users may delete Devolutions", Devolutions, "O:SYD:(A;;SD;;;BU)", "Access " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users may change the DACL", Devolutions, "O:SYD:(A;;WD;;;BU)", "Access " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users may take ownership", Devolutions, "O:SYD:(A;;WO;;;BU)", "Access " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users may delete entries", Devolutions, "O:SYD:(A;;0x40;;;BU)", "Access " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users have generic all", Devolutions, "O:SYD:(A;;GA;;;BU)", "Access " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users may delete through a conditional entry", Devolutions, "O:SYD:(XA;;SD;;;BU;(Member_of {SID(BU)}))", "Access " + Users)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("null DACL", Devolutions, "O:SYD:NO_ACCESS_CONTROL", "Access " + Everyone)]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users get full control of entries created below", Devolutions, "O:SYD:(A;OICIIO;FA;;;BU)", "none")]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users may only add entries", Devolutions, "O:SYD:(A;CI;DCLCRPCR;;;BU)", "none")]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("Users are denied deletion", Devolutions, "O:SYD:(D;;SD;;;BU)", "none")]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("TrustedInstaller has full control", Devolutions, "O:SYD:(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)", "none")]
    // oracle: reference crates/now-package-broker/src/policy_security.rs verify_policy_ancestor_directory_security
    [InlineData("no owner", Devolutions, "D:(A;;FA;;;SY)", "Unreadable")]
    // oracle: scaffold
    [InlineData("Users may delete through an object entry", Devolutions, "O:SYD:(OA;;SD;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", "Access " + Users)]
    // oracle: scaffold
    [InlineData("Users have full control of Agent", Agent, "O:SYD:(A;OICI;FA;;;BU)", "none")]
    public void RefusalFollowsTheOwnerAndTheDacl(string scenario, bool checkAccess, string sddl, string expected)
    {
        DataFolderRefusal refusal = DataFolders.Evaluate("folder", new RawSecurityDescriptor(sddl), false, checkAccess);

        Assert.True(expected == Describe(refusal), $"{scenario}: {Describe(refusal)}");
    }

    // oracle: reference crates/now-package-broker/src/policy_security.rs retain_policy_no_reparse_directory_chain
    [Theory]
    [InlineData(Devolutions)]
    [InlineData(Agent)]
    public void LinkIsRefusedWhateverItsSecurity(bool checkAccess)
    {
        DataFolderRefusal refusal = DataFolders.Evaluate(
            "folder", new RawSecurityDescriptor("O:SY" + InheritedDacl), true, checkAccess);

        Assert.Equal("Link", Describe(refusal));
    }

    // oracle: reference crates/now-package-broker/src/policy_security.rs retain_policy_no_reparse_directory_chain
    [Fact]
    public void CheckRefusesAJunctionAtDevolutions()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        TempFolder.CreateJunction(devolutions, folder.CreateDirectory("target"));

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "Link"), (refusal?.Folder, Describe(refusal)));
    }

    [Fact]
    public void CreateRefusesAJunctionAtDevolutionsAndCreatesNothingInItsTarget()
    {
        using TempFolder folder = new();
        string target = folder.CreateDirectory("target");
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        TempFolder.CreateJunction(devolutions, target);

        DataFolderRefusal refusal = DataFolders.Create(folder.Path, AgentSddl, this.logger);

        // oracle: reference crates/now-package-broker/src/policy_security.rs retain_policy_no_reparse_directory_chain
        Assert.Equal((devolutions, "Link"), (refusal?.Folder, Describe(refusal)));
        // oracle: scaffold
        Assert.Empty(Directory.GetFileSystemEntries(target));
    }

    // oracle: scaffold
    [Fact]
    public void CheckRefusesADevolutionsFolderWhoseEntriesUsersMayDelete()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        Assert.True(SecureDirectory.Create(devolutions, ReplaceableByUsersSddl));

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "Access " + Users), (refusal?.Folder, Describe(refusal)));
    }

    // oracle: scaffold
    [Fact]
    public void CreateRefusesADevolutionsFolderWhoseEntriesUsersMayDeleteAndCreatesNothingInIt()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        Assert.True(SecureDirectory.Create(devolutions, ReplaceableByUsersSddl));

        DataFolderRefusal refusal = DataFolders.Create(folder.Path, AgentSddl, this.logger);

        Assert.Equal((devolutions, "Access " + Users), (refusal?.Folder, Describe(refusal)));
        Assert.Empty(Directory.GetFileSystemEntries(devolutions));
    }

    // oracle: scaffold
    [Fact]
    public void CheckRefusesADevolutionsFolderWhoseSecurityItCantRead()
    {
        using TempFolder folder = new();
        string devolutions = Path.Combine(folder.Path, "Devolutions");
        // The OWNER RIGHTS entry takes away the owner's implicit right to read the security descriptor, and the current
        // user keeps only the rights to list the folder, read its attributes and synchronize, which deleting it needs.
        Assert.True(SecureDirectory.Create(devolutions, $"O:{CurrentUser}D:P(A;;0;;;OW)(A;OICI;FA;;;SY)(A;;0x100081;;;{CurrentUser})"));

        DataFolderRefusal refusal = DataFolders.Check(folder.Path, this.logger);

        Assert.Equal((devolutions, "Unreadable"), (refusal?.Folder, Describe(refusal)));
    }

    // oracle: scaffold
    [Fact]
    public void CheckPassesWhenTheFoldersDontExist()
    {
        using TempFolder folder = new();

        Assert.Null(DataFolders.Check(folder.Path, this.logger));
    }

    // oracle: scaffold
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

    // oracle: scaffold
    [Fact]
    public void ErrorIsInTheInstallerLanguage()
    {
        DataFolderRefusal refusal = new(@"C:\ProgramData\Devolutions", DataFolderProblem.Link);
        string english = refusal.Message("1033");

        Assert.NotEqual(english, refusal.Message("1036"));
        Assert.NotEqual(english, refusal.Message("1053"));
        // Windows Installer applies no language transform for German, so the rest of the installer is in English too.
        Assert.Equal(english, refusal.Message("1031"));
    }

    // oracle: spec .agents/skills/installer-localization/SKILL.md §Change strings
    [Theory]
    [InlineData(Strings.DataFolderIsLink)]
    [InlineData(Strings.DataFolderOwnedByUntrustedAccount)]
    [InlineData(Strings.DataFolderReplaceableByUntrustedAccount)]
    [InlineData(Strings.DataFolderSecurityUnreadable)]
    public void ErrorIsTranslatedWithTheEnglishPlaceholders(string id)
    {
        string english = Program.Localize("1033", id);

        Assert.NotEqual(id, english);
        Assert.All(new[] { "1036", "1053" }, language =>
        {
            string translated = Program.Localize(language, id);
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

        // oracle: scaffold
        Assert.Equal(Return.check, action.Return);
        // A deferred action reads only the properties its action data carries.
        // oracle: spec Windows Installer §Obtaining Context Information for Deferred Execution Custom Actions
        Assert.Contains("ProductLanguage=[ProductLanguage]", action.UsesProperties.Split(';'));
    }

    [Theory]
    // oracle: scaffold
    [InlineData("first install", true)]
    // oracle: scaffold
    [InlineData("major upgrade", true, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}")]
    // oracle: scaffold
    [InlineData("repair", true, "Installed=00:00:00", "REINSTALL=ALL")]
    // oracle: scaffold
    [InlineData("maintenance adding a feature", true, "Installed=00:00:00", "ADDLOCAL=F.Session")]
    // oracle: scaffold
    [InlineData("maintenance removing a feature", true, "Installed=00:00:00", "REMOVE=F.Session")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("full uninstall", false, "Installed=00:00:00", "REMOVE=ALL")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("old product removed by a major upgrade", false, "Installed=00:00:00", "REMOVE=ALL", "UPGRADINGPRODUCTCODE={00000000-0000-0000-0000-000000000002}")]
    public void DataFoldersAreCheckedOnEveryRunButAFullUninstall(string scenario, bool expected, params string[] properties)
    {
        bool[] evaluated = DataFolderActions
            .Select(method => EvaluateCondition(ActionOf(method).Condition.ToString(), properties))
            .ToArray();

        Assert.True(evaluated.All(e => e == expected), $"{scenario}: {string.Join(", ", evaluated)}");
    }

    // oracle: scaffold
    [Fact]
    public void CheckRunsBeforeTheMajorUpgradeRemovesTheInstalledProduct()
    {
        Assert.Equal(When.Before, AgentActions.checkProgramDataDirectory.When);
        Assert.Equal(Step.RemoveExistingProducts.ToString(), AgentActions.checkProgramDataDirectory.Step.ToString());
    }

    /// <summary>
    /// The problem and the account <paramref name="refusal"/> names, or <c>none</c>.
    /// </summary>
    private static string Describe(DataFolderRefusal refusal) =>
        refusal is null ? "none" : $"{refusal.Problem} {refusal.Account}".TrimEnd();

    private static string[] Placeholders(string text) =>
        Regex.Matches(text, @"\{\d+\}").Cast<Match>().Select(m => m.Value).OrderBy(p => p).ToArray();
}
