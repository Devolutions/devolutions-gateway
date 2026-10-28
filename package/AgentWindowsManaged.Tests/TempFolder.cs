using System;
using System.Diagnostics;
using System.IO;

using Xunit;

namespace DevolutionsAgent.Installer.Tests;

/// <summary>
/// A new, empty folder under the temporary directory, deleted with its content on disposal.
/// </summary>
internal sealed class TempFolder : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"installer-tests-{Guid.NewGuid():N}");

    public TempFolder() => Directory.CreateDirectory(this.Path);

    /// <summary>
    /// Creates the directory <paramref name="names"/> below this folder, with its parents.
    /// </summary>
    public string CreateDirectory(params string[] names) =>
        Directory.CreateDirectory(System.IO.Path.Combine([this.Path, .. names])).FullName;

    /// <summary>
    /// Creates a junction at <paramref name="link"/> to the directory <paramref name="target"/>, which needs no
    /// elevation.
    /// </summary>
    public static void CreateJunction(string link, string target)
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
