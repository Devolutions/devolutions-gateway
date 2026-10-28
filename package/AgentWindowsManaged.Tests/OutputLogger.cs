using DevolutionsAgent.Actions;

using Xunit.Abstractions;

namespace DevolutionsAgent.Installer.Tests;

/// <summary>
/// Writes the log of the code under test to the test's output.
/// </summary>
internal sealed class OutputLogger(ITestOutputHelper output) : ILogger
{
    public void Log(string msg) => output.WriteLine(msg);

    public void Log(string format, params object[] args) => output.WriteLine(format, args);
}
