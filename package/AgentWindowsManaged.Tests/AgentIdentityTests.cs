using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using DevolutionsAgent.Actions;
using DevolutionsAgent.Helpers;

using Microsoft.Deployment.WindowsInstaller;

using WixSharp;

using Xunit;

using MsiInstaller = Microsoft.Deployment.WindowsInstaller.Installer;
using Property = WixSharp.Property;
using Record = Microsoft.Deployment.WindowsInstaller.Record;

namespace DevolutionsAgent.Installer.Tests;

public sealed class AgentIdentityTests
{
    // A well-formed token (crates/agent-identity/src/token.rs) whose bag names https://example.test/dvls.
    private const string Token = "dvaet1.eyJ1IjoiaHR0cHM6Ly9leGFtcGxlLnRlc3QvZHZscyJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // The secret part of Token, after its last `.`.
    private const string TokenSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Theory]
    [InlineData("IDENTITY_ENROLLMENT_TOKEN")]
    [InlineData("IDENTITY_ENROLLMENT_TOKEN_ENCODED")]
    public void TokenPropertiesAreHiddenAndSecure(string id)
    {
        // Hidden lists the property in MsiHiddenProperties, which keeps its value out of the MSI log.
        // Secure lets a value given on the msiexec command line reach the elevated execute sequence.
        Property property = Assert.Single(Program.CreateIdentityEnrollmentProperties(), p => p.Name == id);

        Assert.True(property.Hidden);
        // oracle: spec Windows Installer §SecureCustomProperties property
        Assert.True(property.Secure);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    // oracle: spec Windows Installer §SecureCustomProperties property
    [Fact]
    public void TokenFilePropertyIsSecure()
    {
        // Secure lets a path given on the msiexec command line reach the execute sequence, which reads the file.
        Property property = Assert.Single(
            Program.CreateIdentityEnrollmentProperties(), p => p.Name == "IDENTITY_ENROLLMENT_TOKEN_FILE");

        Assert.True(property.Secure);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    // oracle: spec Windows Installer §Custom Action In-Script Execution Options
    [Fact]
    public void EnrollmentRunsDeferredAsSystemAndFailsTheInstall()
    {
        ElevatedManagedAction action = AgentActions.enrollAgentIdentity;

        Assert.Contains(action, AgentActions.Actions);
        Assert.Equal(Execute.deferred, action.Execute);
        Assert.False(action.Impersonate);
        // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
        Assert.Equal(Return.check, action.Return);
        // HideTarget keeps the CustomActionData out of the MSI log, and WiX hides the property that carries it.
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
        // oracle: spec Windows Installer §Custom Action Hidden Target Option
        Assert.Contains("HideTarget=yes", action.AttributesDefinition);
        // The deferred action receives the token only in its encoded form.
        // oracle: mutant the action data omits INSTALLDIR, so the deferred action can't locate the agent executable
        Assert.Equal(
            ["IDENTITY_ENROLLMENT_TOKEN_ENCODED=[IDENTITY_ENROLLMENT_TOKEN_ENCODED]", "INSTALLDIR=[INSTALLDIR]"],
            action.UsesProperties.Split(';'));
    }

    // oracle: mutant enrollment is sequenced before config init, which creates agent.json
    [Fact]
    public void EnrollmentRunsAfterConfigInitAndBeforeTheServiceStarts()
    {
        // config init creates agent.json from the installed executable before the service starts, and the service
        // consumes the pending file when it starts.
        Assert.Equal(When.After, AgentActions.enrollAgentIdentity.When);
        Assert.Equal(AgentActions.initAgentConfigIfNeeded.Id, AgentActions.enrollAgentIdentity.Step.ToString());
        Assert.Equal(When.After, AgentActions.initAgentConfigIfNeeded.When);
        Assert.Equal(AgentActions.cleanAgentConfigIfNeeded.Id, AgentActions.initAgentConfigIfNeeded.Step.ToString());
        Assert.Equal(When.Before, AgentActions.cleanAgentConfigIfNeeded.When);
        Assert.Equal(Step.StartServices.ToString(), AgentActions.cleanAgentConfigIfNeeded.Step.ToString());
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    // oracle: intent crates/device-key/INTENT.md §Access
    // oracle: spec Windows Installer §Custom Action In-Script Execution Options
    [Fact]
    public void CleanupRunsDeferredAsSystemAfterTheFilesAreRemovedAndNeverFailsTheUninstall()
    {
        ElevatedManagedAction action = AgentActions.removeAgentIdentity;

        Assert.Contains(action, AgentActions.Actions);
        Assert.Equal(Execute.deferred, action.Execute);
        Assert.False(action.Impersonate);
        // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
        Assert.Equal(Return.ignore, action.Return);
        // RemoveFiles runs after StopServices, so the stopped service holds neither the state lock nor a key.
        // oracle: mutant the cleanup runs before StopServices, while the service may hold the state lock and keys
        Assert.Equal(When.After, action.When);
        Assert.Equal(Step.RemoveFiles.ToString(), action.Step.ToString());
    }

    [Theory]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("first install with a token", true, "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("major upgrade with a token", true, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("first install without a token", false)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("major upgrade without a token", false, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("maintenance with a token", false, "Installed=00:00:00", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("repair with a token", false, "Installed=00:00:00", "REINSTALL=ALL", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("full uninstall with a token", false, "Installed=00:00:00", "REMOVE=ALL", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    public void EnrollmentRunsOnlyOnAnInstallOrUpgradeWithAToken(string scenario, bool expected, params string[] properties)
    {
        Assert.True(
            expected == EvaluateCondition(AgentActions.enrollAgentIdentity.Condition.ToString(), properties),
            scenario);
    }

    [Theory]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("full uninstall", true, "Installed=00:00:00", "REMOVE=ALL")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("old product removed by a major upgrade", false, "Installed=00:00:00", "REMOVE=ALL", "UPGRADINGPRODUCTCODE={00000000-0000-0000-0000-000000000002}")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("new product of a major upgrade", false, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("first install", false)]
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    [InlineData("repair", false, "Installed=00:00:00", "REINSTALL=ALL")]
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    [InlineData("maintenance removing a feature", false, "Installed=00:00:00", "REMOVE=F.Session")]
    public void CleanupRunsOnlyOnAFullUninstall(string scenario, bool expected, params string[] properties)
    {
        Assert.True(
            expected == EvaluateCondition(AgentActions.removeAgentIdentity.Condition.ToString(), properties),
            scenario);
    }

    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    [Fact]
    public void EnrollCommandPassesTheTokenOnlyThroughStandardInput()
    {
        // `identity enroll -` reads the token from the first line of standard input, so that it never appears in a
        // process listing.
        (string fileName, string arguments, string input) = AgentIdentity.EnrollCommand(@"C:\Program Files\Devolutions\Agent\", Token);

        // oracle: mutant the command names the executable without the install directory
        Assert.Equal(@"C:\Program Files\Devolutions\Agent\DevolutionsAgent.exe", fileName);
        Assert.Equal("identity enroll -", arguments);
        Assert.Equal(Token + "\n", input);
    }

    // oracle: intent crates/device-key/INTENT.md §Key name
    // oracle: intent crates/device-key/INTENT.md §Operations
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    [Theory]
    [InlineData("devolutions-agent-identity_0b9f3c4e-6a1d-4f0e-9a8b-2c7d5e1f3a6b", true)]
    [InlineData("devolutions-agent-identity_a", true)]
    [InlineData("devolutions-agent-identity_part_with-separators_0", true)]
    [InlineData("devolutions-agent-identity-test_0b9f3c4e", false)]
    [InlineData("devolutions-agent_identity_0b9f3c4e", false)]
    [InlineData("other_devolutions-agent-identity_0b9f3c4e", false)]
    [InlineData("devolutions-agent-identity", false)]
    [InlineData("devolutions-agent-identity_", false)]
    [InlineData("Devolutions-Agent-Identity_0b9f3c4e", false)]
    [InlineData("devolutions-agent-identity_0B9F3C4E", false)]
    [InlineData("devolutions-agent-identity_part.with.dot", false)]
    [InlineData("devolutions-agent-identity_part with space", false)]
    [InlineData("devolutions-agent-identity_é", false)]
    [InlineData("", false)]
    public void KeyNameMatchesTheAgentPrefixByTheListingRule(string name, bool expected)
    {
        // Listing under a prefix returns only well-formed names whose part before the first `_` equals that prefix, and
        // the part after `_` is 1 to 128 of `a`-`z`, `0`-`9`, `-` and `_`.
        Assert.Equal(expected, AgentIdentity.IsKeyName(name));
    }

    // oracle: intent crates/device-key/INTENT.md §Key name
    [Fact]
    public void KeyNameAcceptsAPartOfAtMost128Characters()
    {
        Assert.True(AgentIdentity.IsKeyName("devolutions-agent-identity_" + new string('a', 128)));
        Assert.False(AgentIdentity.IsKeyName("devolutions-agent-identity_" + new string('a', 129)));
    }

    // oracle: property round-trip
    [Fact]
    public void ErrorMessageShowsAgentOutputVerbatim()
    {
        // The installer formats an error message, so unescaped agent output would lose `[ERROR]` and could expand a
        // property such as CustomActionData, which holds the encoded token in the enrollment action.
        const string Output = "[ERROR] enrollment failed: [SECRET] ]x[ [[1]] [\\[]";

        string shown = WithSession(["SECRET=value"], session =>
        {
            using Record record = new(0) { FormatString = CustomActions.EscapeFormatted(Output) };
            return session.FormatRecord(record);
        });

        Assert.Equal(Output, shown);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    // oracle: spec Windows Installer §Deferred Execution Custom Actions
    [Fact]
    public void TokenFileIsReadBeforeTheTokenIsEncodedAndFailsTheInstall()
    {
        // The enrollment action receives the encoded token, which EncodePropertyData copies from
        // IDENTITY_ENROLLMENT_TOKEN, and only an immediate action can set that property for a later action.
        ManagedAction action = ActionOf(nameof(CustomActions.ReadIdentityEnrollmentTokenFile));

        Assert.Equal(Execute.immediate, action.Execute);
        Assert.Equal(Return.check, action.Return);
        Assert.Equal(When.Before, action.When);
        // oracle: mutant the file is read after EncodePropertyData copied an empty token
        Assert.Equal(ActionOf(nameof(CustomActions.EncodePropertyData)).Id.ToString(), action.Step.ToString());
    }

    [Theory]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("first install with a token file", true, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("major upgrade with a token file", true, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}", "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("first install without a token file", false)]
    // Enrollment never runs on these, so a token file that is gone by then must not fail them.
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("maintenance with a token file", false, "Installed=00:00:00", "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("repair with a token file", false, "Installed=00:00:00", "REINSTALL=ALL", "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("full uninstall with a token file", false, "Installed=00:00:00", "REMOVE=ALL", "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt")]
    public void TokenFileIsReadOnlyOnAnInstallOrUpgradeThatNamesOne(string scenario, bool expected, params string[] properties)
    {
        ManagedAction action = ActionOf(nameof(CustomActions.ReadIdentityEnrollmentTokenFile));

        Assert.True(expected == EvaluateCondition(action.Condition.ToString(), properties), scenario);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void TokenFileRelativePathResolvesAgainstTheInstallerFolder()
    {
        // The package's folder isn't the working directory, which holds no file of that name.
        using TempFolder folder = new();
        string name = $"token-{Guid.NewGuid():N}.txt";
        System.IO.File.WriteAllText(Path.Combine(folder.Path, name), Token + "\r\n");

        (ActionResult result, string token, _) = ReadTokenFile(folder.Path, "IDENTITY_ENROLLMENT_TOKEN_FILE=" + name);

        Assert.Equal(ActionResult.Success, result);
        Assert.Equal(Token, token);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Theory]
    [InlineData("")]
    [InlineData("\r\n")]
    [InlineData("\n")]
    [InlineData("\r\nsecond line\r\n")]
    public void TokenIsTheFirstLineOfTheFile(string afterToken)
    {
        using TempFolder folder = new();
        System.IO.File.WriteAllText(Path.Combine(folder.Path, "token.txt"), Token + afterToken);

        (_, string token, _) = ReadTokenFile(folder.Path, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt");

        Assert.Equal(Token, token);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Theory]
    // UTF-8 with a byte order mark, as Windows PowerShell's `Set-Content -Encoding UTF8` writes it.
    // oracle: spec RFC 3629 §6
    [InlineData(65001)]
    // UTF-16 LE with a byte order mark, as Windows PowerShell's `Out-File` and `>` write it.
    // oracle: spec RFC 2781 §3.2
    [InlineData(1200)]
    public void ByteOrderMarkIsNotPartOfTheToken(int codePage)
    {
        // A byte order mark labels the encoding and isn't part of the text.
        Encoding encoding = Encoding.GetEncoding(codePage);
        using TempFolder folder = new();
        System.IO.File.WriteAllBytes(
            Path.Combine(folder.Path, "token.txt"),
            [.. encoding.GetPreamble(), .. encoding.GetBytes(Token + "\r\n")]);

        (_, string token, _) = ReadTokenFile(folder.Path, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt");

        Assert.Equal(Token, token);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void MissingTokenFileFailsTheInstall()
    {
        using TempFolder folder = new();

        (ActionResult result, _, _) = ReadTokenFile(folder.Path, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt");

        Assert.Equal(ActionResult.Failure, result);
    }

    [Theory]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("")]
    // A blank first line holds no token, and an install that went on without one would report success for a machine
    // that can't enroll.
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData("\r\n" + Token + "\r\n")]
    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [InlineData(" \t\r\n" + Token + "\r\n")]
    public void TokenFileWithoutATokenOnItsFirstLineFailsTheInstall(string content)
    {
        using TempFolder folder = new();
        System.IO.File.WriteAllText(Path.Combine(folder.Path, "token.txt"), content);

        (ActionResult result, _, _) = ReadTokenFile(folder.Path, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt");

        Assert.Equal(ActionResult.Failure, result);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Fact]
    public void SettingBothTokenPropertiesFailsTheInstall()
    {
        // Both name the same token, so only the use of both properties can fail the install.
        using TempFolder folder = new();
        System.IO.File.WriteAllText(Path.Combine(folder.Path, "token.txt"), Token + "\r\n");

        (ActionResult result, _, _) = ReadTokenFile(
            folder.Path, "IDENTITY_ENROLLMENT_TOKEN=" + Token, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt");

        Assert.Equal(ActionResult.Failure, result);
    }

    // oracle: intent package/AgentWindowsManaged/INTENT.md §Agent Identity
    [Theory]
    [InlineData("token read", Token + "\r\n")]
    [InlineData("first line blank", "\r\n" + Token + "\r\n")]
    [InlineData("both properties set", Token + "\r\n", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    public void InstallerNeverDeletesTheTokenFile(string scenario, string content, params string[] properties)
    {
        using TempFolder folder = new();
        string path = Path.Combine(folder.Path, "token.txt");
        System.IO.File.WriteAllText(path, content);

        ReadTokenFile(folder.Path, [.. properties, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt"]);

        Assert.True(System.IO.File.Exists(path), scenario);
    }

    // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
    [Theory]
    [InlineData("token read", Token + "\r\n")]
    [InlineData("first line blank", "\r\n" + Token + "\r\n")]
    [InlineData("both properties set", Token + "\r\n", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    public void TokenFileNeverPutsTheTokenInAMessage(string scenario, string content, params string[] properties)
    {
        // Every message the session sends, an error shown to the user included, also goes to the installer log.
        using TempFolder folder = new();
        System.IO.File.WriteAllText(Path.Combine(folder.Path, "token.txt"), content);

        (_, _, List<(InstallMessage Type, string Text)> messages) =
            ReadTokenFile(folder.Path, [.. properties, "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt"]);

        string leak = messages.Select(m => m.Text).FirstOrDefault(m => m.Contains(TokenSecret));
        Assert.True(leak is null, $"{scenario}: {leak}");
    }

    // oracle: mutant the error ignores the installer's language
    [Fact]
    public void TokenFileErrorIsInTheInstallerLanguage()
    {
        using TempFolder folder = new();

        string ErrorIn(string productLanguage)
        {
            (_, _, List<(InstallMessage Type, string Text)> messages) = ReadTokenFile(
                folder.Path,
                "ProductLanguage=" + productLanguage,
                "IDENTITY_ENROLLMENT_TOKEN=" + Token,
                "IDENTITY_ENROLLMENT_TOKEN_FILE=token.txt");

            return Assert.Single(messages, m => m.Type == InstallMessage.Error).Text;
        }

        string english = ErrorIn("1033");

        Assert.NotEqual(english, ErrorIn("1036"));
        Assert.NotEqual(english, ErrorIn("1053"));
        // Windows Installer applies no language transform for German, so the rest of the installer is in English too.
        Assert.Equal(english, ErrorIn("1031"));
    }

    /// <summary>
    /// The installer's action that runs the custom action <paramref name="methodName"/>.
    /// </summary>
    private static ManagedAction ActionOf(string methodName) =>
        Assert.Single(AgentActions.Actions.OfType<ManagedAction>(), a => a.MethodName == methodName);

    /// <summary>
    /// Runs the custom action that reads the enrollment token file, in a session of a package in
    /// <paramref name="folder"/> where <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    /// <returns>
    /// The action's result, the token it leaves in <c>IDENTITY_ENROLLMENT_TOKEN</c>, and every message the session
    /// sent, log lines included.
    /// </returns>
    private static (ActionResult Result, string Token, List<(InstallMessage Type, string Text)> Messages) ReadTokenFile(
        string folder, params string[] properties)
    {
        List<(InstallMessage Type, string Text)> messages = [];
        ExternalUIHandler previous = MsiInstaller.SetExternalUI(
            (ExternalUIHandler)((type, message, _, _, _) =>
            {
                if (message is not null)
                {
                    messages.Add((type, message));
                }

                return MessageResult.OK;
            }),
            InstallLogModes.FatalExit | InstallLogModes.Error | InstallLogModes.Warning | InstallLogModes.User
            | InstallLogModes.Info | InstallLogModes.Verbose | InstallLogModes.ExtraDebug);

        try
        {
            return WithSession(folder, properties, session =>
            {
                ActionResult result = CustomActions.ReadIdentityEnrollmentTokenFile(session);
                return (result, session["IDENTITY_ENROLLMENT_TOKEN"], messages);
            });
        }
        finally
        {
            MsiInstaller.SetExternalUI(previous, InstallLogModes.None);
        }
    }

    /// <summary>
    /// Evaluates <paramref name="condition"/> with the Windows Installer engine, in a session where
    /// <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    private static bool EvaluateCondition(string condition, string[] properties) =>
        WithSession(properties, session => session.EvaluateCondition(condition));

    private static T WithSession<T>(string[] properties, Func<Session, T> action) =>
        WithSession(AppContext.BaseDirectory, properties, action);

    /// <summary>
    /// Runs <paramref name="action"/> in a Windows Installer session of an empty package in <paramref name="folder"/>
    /// where <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    private static T WithSession<T>(string folder, string[] properties, Func<Session, T> action)
    {
        string path = Path.Combine(folder, $"session-{Guid.NewGuid():N}.msi");

        try
        {
            using (Database database = new(path, DatabaseOpenMode.CreateDirect))
            {
                database.Execute("CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL LOCALIZABLE PRIMARY KEY `Property`)");
                database.Execute($"INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductCode', '{Guid.NewGuid():B}')");
                database.SummaryInfo.Template = "x64;1033";
                database.SummaryInfo.RevisionNumber = Guid.NewGuid().ToString("B");
                database.SummaryInfo.PageCount = 500;
                database.Commit();
            }

            using Session session = MsiInstaller.OpenPackage(path, ignoreMachineState: true);

            foreach (string property in properties)
            {
                string[] parts = property.Split(['='], 2);
                session[parts[0]] = parts[1];
            }

            return action(session);
        }
        finally
        {
            System.IO.File.Delete(path);
        }
    }

    /// <summary>
    /// A new, empty folder under the temporary directory, deleted with its content on disposal.
    /// </summary>
    private sealed class TempFolder : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"agent-identity-{Guid.NewGuid():N}");

        public TempFolder() => Directory.CreateDirectory(Path);

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
