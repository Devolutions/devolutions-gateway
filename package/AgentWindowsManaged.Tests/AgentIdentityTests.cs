using System;
using System.IO;
using System.Linq;

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

    [Theory]
    [InlineData("IDENTITY_ENROLLMENT_TOKEN")]
    [InlineData("IDENTITY_ENROLLMENT_TOKEN_ENCODED")]
    public void TokenPropertiesAreHiddenAndSecure(string id)
    {
        // Hidden lists the property in MsiHiddenProperties, which keeps its value out of the MSI log.
        // Secure lets a value given on the msiexec command line reach the elevated execute sequence.
        Property property = Assert.Single(Program.CreateIdentityEnrollmentProperties(), p => p.Name == id);

        Assert.True(property.Hidden);
        Assert.True(property.Secure);
    }

    [Fact]
    public void EnrollmentRunsDeferredAsSystemAndFailsTheInstall()
    {
        ElevatedManagedAction action = AgentActions.enrollAgentIdentity;

        Assert.Contains(action, AgentActions.Actions);
        Assert.Equal(Execute.deferred, action.Execute);
        Assert.False(action.Impersonate);
        Assert.Equal(Return.check, action.Return);
        // HideTarget keeps the CustomActionData out of the MSI log, and WiX hides the property that carries it.
        Assert.Contains("HideTarget=yes", action.AttributesDefinition);
        // The deferred action receives the token only in its encoded form.
        Assert.Equal(
            ["IDENTITY_ENROLLMENT_TOKEN_ENCODED=[IDENTITY_ENROLLMENT_TOKEN_ENCODED]", "INSTALLDIR=[INSTALLDIR]"],
            action.UsesProperties.Split(';'));
    }

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

    [Fact]
    public void CleanupRunsDeferredAsSystemAfterTheFilesAreRemovedAndNeverFailsTheUninstall()
    {
        ElevatedManagedAction action = AgentActions.removeAgentIdentity;

        Assert.Contains(action, AgentActions.Actions);
        Assert.Equal(Execute.deferred, action.Execute);
        Assert.False(action.Impersonate);
        Assert.Equal(Return.ignore, action.Return);
        // RemoveFiles runs after StopServices, so the stopped service holds neither the state lock nor a key.
        Assert.Equal(When.After, action.When);
        Assert.Equal(Step.RemoveFiles.ToString(), action.Step.ToString());
    }

    [Theory]
    [InlineData("first install with a token", true, "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    [InlineData("major upgrade with a token", true, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    [InlineData("first install without a token", false)]
    [InlineData("major upgrade without a token", false, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}")]
    [InlineData("maintenance with a token", false, "Installed=00:00:00", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    [InlineData("repair with a token", false, "Installed=00:00:00", "REINSTALL=ALL", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    [InlineData("full uninstall with a token", false, "Installed=00:00:00", "REMOVE=ALL", "IDENTITY_ENROLLMENT_TOKEN=" + Token)]
    public void EnrollmentRunsOnlyOnAnInstallOrUpgradeWithAToken(string scenario, bool expected, params string[] properties)
    {
        Assert.True(
            expected == EvaluateCondition(AgentActions.enrollAgentIdentity.Condition.ToString(), properties),
            scenario);
    }

    [Theory]
    [InlineData("full uninstall", true, "Installed=00:00:00", "REMOVE=ALL")]
    [InlineData("old product removed by a major upgrade", false, "Installed=00:00:00", "REMOVE=ALL", "UPGRADINGPRODUCTCODE={00000000-0000-0000-0000-000000000002}")]
    [InlineData("new product of a major upgrade", false, "WIX_UPGRADE_DETECTED={00000000-0000-0000-0000-000000000001}")]
    [InlineData("first install", false)]
    [InlineData("repair", false, "Installed=00:00:00", "REINSTALL=ALL")]
    [InlineData("maintenance removing a feature", false, "Installed=00:00:00", "REMOVE=F.Session")]
    public void CleanupRunsOnlyOnAFullUninstall(string scenario, bool expected, params string[] properties)
    {
        Assert.True(
            expected == EvaluateCondition(AgentActions.removeAgentIdentity.Condition.ToString(), properties),
            scenario);
    }

    [Fact]
    public void EnrollCommandPassesTheTokenOnlyThroughStandardInput()
    {
        // `identity enroll -` reads the token from the first line of standard input, so that it never appears in a
        // process listing.
        (string fileName, string arguments, string input) = AgentIdentity.EnrollCommand(@"C:\Program Files\Devolutions\Agent\", Token);

        Assert.Equal(@"C:\Program Files\Devolutions\Agent\DevolutionsAgent.exe", fileName);
        Assert.Equal("identity enroll -", arguments);
        Assert.Equal(Token + "\n", input);
    }

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
        // crates/device-key/INTENT.md: listing under a prefix returns only well-formed names whose part before the
        // first `_` equals that prefix, and the part after `_` is 1 to 128 of `a`-`z`, `0`-`9`, `-` and `_`.
        Assert.Equal(expected, AgentIdentity.IsKeyName(name));
    }

    [Fact]
    public void KeyNameAcceptsAPartOfAtMost128Characters()
    {
        Assert.True(AgentIdentity.IsKeyName("devolutions-agent-identity_" + new string('a', 128)));
        Assert.False(AgentIdentity.IsKeyName("devolutions-agent-identity_" + new string('a', 129)));
    }

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

    /// <summary>
    /// Evaluates <paramref name="condition"/> with the Windows Installer engine, in a session where
    /// <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    private static bool EvaluateCondition(string condition, string[] properties) =>
        WithSession(properties, session => session.EvaluateCondition(condition));

    /// <summary>
    /// Runs <paramref name="action"/> in a Windows Installer session of an empty package where
    /// <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    private static T WithSession<T>(string[] properties, Func<Session, T> action)
    {
        string path = Path.Combine(AppContext.BaseDirectory, $"session-{Guid.NewGuid():N}.msi");

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
}
