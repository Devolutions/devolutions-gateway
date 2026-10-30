using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

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

    /// <summary>
    /// Creates a hard link at <paramref name="link"/> to the file <paramref name="target"/>, which needs no elevation.
    /// </summary>
    public static void CreateHardLink(string link, string target)
    {
        Assert.True(CreateHardLinkW(link, target, IntPtr.Zero), $"CreateHardLink failed: {Marshal.GetLastWin32Error()}");
    }

    /// <summary>
    /// Creates the directory <paramref name="path"/> through its <c>\\?\</c> form, which keeps a name that a Win32 path
    /// can't reach, such as one ending in a dot.
    /// </summary>
    public static void CreateVerbatimDirectory(string path)
    {
        Assert.True(
            CreateDirectoryW(VerbatimPrefix + path, IntPtr.Zero),
            $"CreateDirectory failed: {Marshal.GetLastWin32Error()}");
    }

    /// <summary>
    /// Opens the directory <paramref name="path"/> without sharing, as the agent holds <c>identity</c> as its state
    /// lock, so that no other handle that reads, writes or deletes it can be opened until this one is closed.
    /// </summary>
    public static SafeFileHandle HoldWithoutSharing(string path)
    {
        // FILE_TRAVERSE takes part in sharing checks, as the installer's own holds do.
        const uint fileTraverse = 0x20;
        const uint openExisting = 3;
        const uint backupSemantics = 0x02000000;

        SafeFileHandle handle = CreateFileW(path, fileTraverse, 0, IntPtr.Zero, openExisting, backupSemantics, IntPtr.Zero);
        Assert.False(handle.IsInvalid, $"CreateFile failed: {Marshal.GetLastWin32Error()}");
        return handle;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string lpPathName, IntPtr lpSecurityAttributes);

    private const string VerbatimPrefix = @"\\?\";

    public void Dispose()
    {
        // Through the \\?\ form, the paths the deletion builds reach a name ending in a dot.
        string path = VerbatimPrefix + this.Path;

        // A recursive Directory.Delete fails on a junction without elevation, so junctions go first.
        RemoveJunctions(path);
        Directory.Delete(path, recursive: true);
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
