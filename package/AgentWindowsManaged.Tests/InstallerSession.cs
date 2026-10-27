using System;
using System.IO;
using System.Linq;

using DevolutionsAgent.Actions;

using Microsoft.Deployment.WindowsInstaller;

using WixSharp;

using Xunit;

using MsiInstaller = Microsoft.Deployment.WindowsInstaller.Installer;

namespace DevolutionsAgent.Installer.Tests;

/// <summary>
/// The installer's actions, and Windows Installer sessions to evaluate them in.
/// </summary>
internal static class InstallerSession
{
    /// <summary>
    /// The test collection of every test class that opens a session.
    /// </summary>
    /// <remarks>
    /// Windows Installer opens one package at a time in a process, and xUnit runs the tests of one collection one at a
    /// time.
    /// </remarks>
    public const string Collection = "Windows Installer session";

    /// <summary>
    /// The installer's action that runs the custom action <paramref name="methodName"/>.
    /// </summary>
    public static ManagedAction ActionOf(string methodName) =>
        Assert.Single(AgentActions.Actions.OfType<ManagedAction>(), a => a.MethodName == methodName);

    /// <summary>
    /// Evaluates <paramref name="condition"/> with the Windows Installer engine, in a session where
    /// <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    public static bool EvaluateCondition(string condition, string[] properties) =>
        WithSession(properties, session => session.EvaluateCondition(condition));

    public static T WithSession<T>(string[] properties, Func<Session, T> action) =>
        WithSession(AppContext.BaseDirectory, properties, action);

    /// <summary>
    /// Runs <paramref name="action"/> in a Windows Installer session of an empty package in <paramref name="folder"/>
    /// where <paramref name="properties"/> (<c>NAME=value</c>) are set.
    /// </summary>
    public static T WithSession<T>(string folder, string[] properties, Func<Session, T> action)
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
}
