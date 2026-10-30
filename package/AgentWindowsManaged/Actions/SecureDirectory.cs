using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace DevolutionsAgent.Actions;

/// <summary>
/// Directory operations that act on the entry a path names, never on the target of a link at that path.
/// </summary>
/// <remarks>
/// Each path is opened with <c>FILE_FLAG_OPEN_REPARSE_POINT</c>, which opens a junction or a symbolic link itself, and
/// every decision is taken from the opened handle, so a link swapped in after a check is never followed.
/// </remarks>
internal static class SecureDirectory
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);

    /// <summary>
    /// NT SERVICE\TrustedInstaller, the Windows Modules Installer service.
    /// </summary>
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>
    /// The share mode of a handle that holds its entry: renaming or replacing an entry needs delete access to it, which
    /// this denies, so no path through a held directory can be redirected to another folder.
    /// </summary>
    private static readonly uint HeldShare = WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE;

    private static readonly uint AnyShare = WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE | WinAPI.FILE_SHARE_DELETE;

    /// <summary>
    /// How long <see cref="Hold"/> retries a directory another process holds without sharing.
    /// </summary>
    private static readonly TimeSpan HoldRetry = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan HoldRetryStep = TimeSpan.FromMilliseconds(25);

    /// <summary>
    /// Creates the directory <paramref name="path"/> with the security descriptor <paramref name="sddl"/>, so that it
    /// never exists with the DACL it would inherit from its parent, or with the security it inherits when
    /// <paramref name="sddl"/> is <c>null</c>.
    /// </summary>
    /// <returns><c>false</c> when an entry named <paramref name="path"/> already exists, which is left unchanged.</returns>
    internal static bool Create(string path, string sddl)
    {
        using SecurityDescriptor descriptor = sddl is null ? null : new(sddl);
        WinAPI.SECURITY_ATTRIBUTES attributes = new()
        {
            nLength = (uint)Marshal.SizeOf<WinAPI.SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = descriptor?.Pointer ?? IntPtr.Zero,
        };

        if (WinAPI.CreateDirectory(path, ref attributes))
        {
            return true;
        }

        int error = Marshal.GetLastWin32Error();

        if (error == WinAPI.ERROR_ALREADY_EXISTS)
        {
            return false;
        }

        throw new Win32Exception(error);
    }

    /// <summary>
    /// Sets the owner and the DACL of the directory
    /// <c><paramref name="root"/>\<paramref name="names"/>[0]\…\<paramref name="names"/>[n-1]</c> to those of
    /// <paramref name="sddl"/>, without following any link.
    /// </summary>
    /// <remarks>
    /// Each directory above the target is held while the next one is opened, so the target is below the directories
    /// checked.
    /// </remarks>
    /// <exception cref="IOException">An entry on the path is a reparse point or not a directory.</exception>
    internal static void SetSecurity(string root, string[] names, string sddl)
    {
        List<SafeFileHandle> parents = new();

        try
        {
            string path = root;

            foreach (string name in names.Take(names.Length - 1))
            {
                path = Path.Combine(path, name);
                SafeFileHandle parent = Hold(path);
                parents.Add(parent);

                if (!IsPlainDirectory(GetAttributes(parent)))
                {
                    throw new IOException($"{path} is a reparse point or not a directory");
                }
            }

            string target = Path.Combine(path, names[names.Length - 1]);
            using SafeFileHandle handle = OpenToSetSecurity(target);
            SetSecurity(handle, target, sddl);
        }
        finally
        {
            parents.ForEach(parent => parent.Dispose());
        }
    }

    /// <summary>
    /// Sets the owner and the DACL of the directory <paramref name="directory"/> holds, opened from
    /// <paramref name="path"/> by <see cref="HoldToSetSecurity"/>, to those of <paramref name="sddl"/>, then removes each
    /// allow entry for LOCAL SERVICE from the DACL of every file and directory below it, without following any link,
    /// unless it finds an entry whose owner <paramref name="isTrusted"/> rejects.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Earlier installers gave LOCAL SERVICE write access on the directory, which the entries below hold as inherited
    /// entries, or as explicit ones where their DACL is protected or not marked auto-inherited, so every allow entry for
    /// LOCAL SERVICE goes, explicit or inherited.
    /// Each entry keeps its other entries, in their order, and its DACL's control flags, such as its protection and its
    /// auto-inherited mark, and a DACL without an allow entry for LOCAL SERVICE isn't written, rather than reset to what
    /// <paramref name="sddl"/> passes on, because the agent refuses its identity directories and files unless they keep
    /// exactly the DACL it provisions.
    /// </para>
    /// <para>
    /// An owner can always change its entry's DACL, so an entry another account, such as LOCAL SERVICE, created below the
    /// directory while it could would keep that access.
    /// The walk checks a directory's owner before it lists the directory, and an entry's owner before it changes the
    /// entry's DACL, and stops at the first owner <paramref name="isTrusted"/> rejects; owners never change, so that a
    /// deployment never silently takes over an entry another account created.
    /// The entries walked before keep their changes, which is harmless, because removing LOCAL SERVICE allow entries never
    /// widens any account's access.
    /// </para>
    /// <para>
    /// Each directory is held while the entries below it are opened, so no path below it can be redirected.
    /// A reparse point, such as a junction or a symbolic link, is never followed, and loses LOCAL SERVICE allow entries
    /// from its own DACL like any other entry, because write access on a link lets an account retarget or remove it;
    /// what it points to is unchanged.
    /// A file's security descriptor is shared by all its names, some of which may be outside the tree, which is harmless,
    /// because removing LOCAL SERVICE allow entries never widens any account's access.
    /// A directory replaced while the walk reaches it fails the walk.
    /// An entry that can't be found by the name its directory listed it under, because it was deleted after the listing
    /// or because a Win32 path can't reach its name, such as one ending in a dot, is skipped: a deleted entry has no DACL
    /// left to change, and neither the installer nor the agent creates such a name, so only an account that could add
    /// entries made it, and that account owns it.
    /// </para>
    /// </remarks>
    /// <param name="isTrusted">Whether an account may own the entry at a path.</param>
    /// <returns>
    /// The refusal for the first entry whose owner <paramref name="isTrusted"/> rejects, or <c>null</c>.
    /// </returns>
    /// <exception cref="IOException">The directory is a reparse point or not a directory.</exception>
    internal static DataFolderRefusal SetSecurityAndRemoveLocalServiceBelow(
        SafeFileHandle directory, string path, string sddl, Func<string, SecurityIdentifier, bool> isTrusted,
        ILogger logger)
    {
        SetSecurity(directory, path, sddl);
        return WalkBelow(path, removeLocalService: true, isTrusted, logger);
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target, to read its security and to
    /// set it with <see cref="SetSecurity(SafeFileHandle, string, string)"/>.
    /// </summary>
    private static SafeFileHandle OpenToSetSecurity(string path) =>
        Open(
            path,
            WinAPI.READ_CONTROL | WinAPI.WRITE_DAC | WinAPI.WRITE_OWNER | WinAPI.FILE_READ_ATTRIBUTES,
            AnyShare);

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target, to read its security and to
    /// set it with <see cref="SetSecurityAndRemoveLocalServiceBelow"/>, holding it as <see cref="Hold"/> does.
    /// </summary>
    internal static SafeFileHandle HoldToSetSecurity(string path) =>
        Hold(path, WinAPI.READ_CONTROL | WinAPI.WRITE_DAC | WinAPI.WRITE_OWNER);

    /// <summary>
    /// Sets the owner and the DACL of the directory <paramref name="handle"/> holds, opened from <paramref name="path"/>
    /// with <c>READ_CONTROL</c>, <c>WRITE_DAC</c> and <c>WRITE_OWNER</c>, to those of <paramref name="sddl"/>.
    /// </summary>
    /// <remarks>
    /// Only the directory changes: unlike <c>SetSecurityInfo</c>, this doesn't propagate inheritable entries to existing
    /// children, so the entries below keep the security they have.
    /// </remarks>
    /// <exception cref="IOException">The entry is a reparse point or not a directory.</exception>
    private static void SetSecurity(SafeFileHandle handle, string path, string sddl)
    {
        if (!IsPlainDirectory(GetAttributes(handle)))
        {
            throw new IOException($"{path} is a reparse point or not a directory");
        }

        using SecurityDescriptor descriptor = new(sddl);

        if (!WinAPI.SetKernelObjectSecurity(
                handle,
                WinAPI.OWNER_SECURITY_INFORMATION | WinAPI.DACL_SECURITY_INFORMATION,
                descriptor.Pointer))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target, to read its security.
    /// </summary>
    /// <param name="hold">Whether to hold the entry as <see cref="Hold"/> does.</param>
    internal static SafeFileHandle OpenToRead(string path, bool hold) =>
        hold
            ? Hold(path, WinAPI.READ_CONTROL)
            : Open(path, WinAPI.READ_CONTROL | WinAPI.FILE_READ_ATTRIBUTES, AnyShare);

    /// <summary>
    /// Opens the directory <paramref name="path"/> names, a link itself rather than its target, with
    /// <paramref name="access"/>, so that it can't be renamed or replaced while the handle is open.
    /// </summary>
    /// <remarks>
    /// A share mode binds only a handle with an access right that takes part in sharing checks, which
    /// <c>READ_CONTROL</c> and <c>FILE_READ_ATTRIBUTES</c> don't, so the handle also has <c>FILE_TRAVERSE</c>, the right
    /// that resolving a path below the directory needs.
    /// A directory another process holds without sharing is retried for <see cref="HoldRetry"/>, because the agent holds
    /// its <c>identity</c> directory that way for a moment around each state write, and keeps running until a major
    /// upgrade stops it.
    /// </remarks>
    internal static SafeFileHandle Hold(string path, uint access = 0)
    {
        Stopwatch elapsed = Stopwatch.StartNew();

        while (true)
        {
            try
            {
                return Open(path, access | WinAPI.FILE_TRAVERSE | WinAPI.FILE_READ_ATTRIBUTES, HeldShare);
            }
            catch (Win32Exception e) when (e.NativeErrorCode == WinAPI.ERROR_SHARING_VIOLATION
                && elapsed.Elapsed < HoldRetry)
            {
                Thread.Sleep(HoldRetryStep);
            }
        }
    }

    /// <summary>
    /// The owner and the DACL of the entry <paramref name="handle"/> holds, whether that entry is a reparse point, and
    /// whether it is a directory.
    /// </summary>
    internal static (RawSecurityDescriptor Security, bool IsReparsePoint, bool IsDirectory) ReadSecurity(
        SafeFileHandle handle)
    {
        uint attributes = GetAttributes(handle);
        bool isReparsePoint = (attributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        bool isDirectory = (attributes & WinAPI.FILE_ATTRIBUTE_DIRECTORY) != 0;
        byte[] descriptor = ReadDescriptor(
            handle, WinAPI.OWNER_SECURITY_INFORMATION | WinAPI.DACL_SECURITY_INFORMATION);

        return (new RawSecurityDescriptor(descriptor, 0), isReparsePoint, isDirectory);
    }

    /// <summary>
    /// Whether <paramref name="sid"/> is SYSTEM, Administrators or TrustedInstaller.
    /// </summary>
    internal static bool IsPrivileged(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid == Administrators || sid == TrustedInstaller;

    /// <summary>
    /// Whether <paramref name="owner"/> may own the agent's data: SYSTEM, Administrators, TrustedInstaller, or a member
    /// of Administrators.
    /// </summary>
    /// <remarks>
    /// Membership is decided as the agent decides it for the owner of a pending-enrollment file
    /// (<c>owner_is_administrator_member</c> in <c>crates/agent-identity/src/windows.rs</c>), so that the installer and the
    /// agent accept the same owners: by the groups Authz resolves for the owner or, when Authz fails, by the local member
    /// list of Administrators.
    /// </remarks>
    /// <exception cref="Win32Exception">Authz failed and the local member list of Administrators can't be read.</exception>
    internal static bool IsTrustedOwner(SecurityIdentifier owner)
    {
        if (IsPrivileged(owner))
        {
            return true;
        }

        // UNTESTED: a member of Administrators, such as an administrator's user account, is trusted through the groups
        // Authz resolves or, when Authz fails, as it may for a domain account, through the local member list.
        // No test runs with such an account, and this keeps the installer accepting the owners the agent accepts.
        // When changing this, keep it in line with owner_is_administrator_member in crates/agent-identity/src/windows.rs.
        List<SecurityIdentifier> groups;

        try
        {
            groups = AuthzGroups(owner);
        }
        catch (Exception)
        {
            return LocalAdministrators().Contains(owner);
        }

        return groups.Contains(Administrators);
    }

    /// <summary>
    /// Deletes <c><paramref name="root"/>\<paramref name="names"/>[0]\…\<paramref name="names"/>[n-1]</c> and everything
    /// below it, without following any link.
    /// </summary>
    /// <remarks>
    /// Every name but the last must be a directory that is not a reparse point, or nothing is deleted.
    /// A reparse point is deleted itself, never its target, and a directory is emptied first.
    /// Each failure is logged and the deletion goes on with the next entry; nothing is thrown.
    /// </remarks>
    internal static void DeleteTree(string root, string[] names, ILogger logger)
    {
        string target = Path.Combine([root, .. names]);

        // UNTESTED: each directory handle stays open until the entries below the directory are done, so that no path
        // below it can be redirected while the deletion runs.
        // Tests check that a held directory can't be renamed, not when the deletion closes its handle.
        // When changing how the deletion opens or closes a directory, keep each handle open that long.
        List<SafeFileHandle> handles = new();

        try
        {
            string path = root;

            foreach (string name in names.Take(names.Length - 1))
            {
                path = Path.Combine(path, name);
                SafeFileHandle parent = Hold(path);
                handles.Add(parent);

                if (!IsPlainDirectory(GetAttributes(parent)))
                {
                    logger.Log($"kept {target}: {path} is a reparse point or not a directory");
                    return;
                }
            }

            SafeFileHandle handle = Open(target, WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES, HeldShare);
            handles.Add(handle);
            Delete(handle, target, logger);
            logger.Log($"deleted {target}");
        }
        catch (Win32Exception e) when (IsNotFound(e))
        {
            // Nothing to delete.
        }
        catch (Exception e)
        {
            logger.Log($"failed to delete {target}: {e}");
        }
        finally
        {
            handles.ForEach(handle => handle.Dispose());
        }
    }

    /// <summary>
    /// Deletes the entry <paramref name="handle"/> holds, after the entries below it when it is a directory that is not a
    /// reparse point.
    /// </summary>
    /// <remarks>
    /// The entry goes once <paramref name="handle"/> is closed.
    /// </remarks>
    private static void Delete(SafeFileHandle handle, string path, ILogger logger)
    {
        if (IsPlainDirectory(GetAttributes(handle)))
        {
            foreach (string entry in Directory.GetFileSystemEntries(path))
            {
                try
                {
                    using SafeFileHandle child = Open(entry, WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES, HeldShare);
                    Delete(child, entry, logger);
                }
                catch (Win32Exception e) when (IsNotFound(e))
                {
                    // Already gone.
                }
                catch (Exception e)
                {
                    logger.Log($"failed to delete {entry}: {e}");
                }
            }
        }

        WinAPI.FILE_DISPOSITION_INFO disposition = new() { DeleteFile = true };

        if (!WinAPI.SetFileInformationByHandle(
                handle,
                WinAPI.FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<WinAPI.FILE_DISPOSITION_INFO>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    /// <summary>
    /// Checks the owner of every file and directory below the directory <paramref name="path"/>, which the caller holds,
    /// without changing anything and without following any link.
    /// </summary>
    /// <remarks>
    /// The entries are opened and held as <see cref="SetSecurityAndRemoveLocalServiceBelow"/> opens and holds them.
    /// </remarks>
    /// <param name="isTrusted">Whether an account may own the entry at a path.</param>
    /// <returns>
    /// The refusal for the first entry whose owner <paramref name="isTrusted"/> rejects, or <c>null</c>.
    /// </returns>
    internal static DataFolderRefusal CheckOwnersBelow(
        string path, Func<string, SecurityIdentifier, bool> isTrusted, ILogger logger) =>
        WalkBelow(path, removeLocalService: false, isTrusted, logger);

    /// <summary>
    /// Checks the owner of every file and directory below the directory <paramref name="path"/>, which the caller holds,
    /// and, when <paramref name="removeLocalService"/> is set, removes each allow entry for LOCAL SERVICE from its DACL,
    /// as <see cref="SetSecurityAndRemoveLocalServiceBelow"/> describes.
    /// </summary>
    /// <returns>
    /// The refusal for the first entry whose owner <paramref name="isTrusted"/> rejects, or <c>null</c>.
    /// </returns>
    private static DataFolderRefusal WalkBelow(
        string path, bool removeLocalService, Func<string, SecurityIdentifier, bool> isTrusted, ILogger logger)
    {
        // UNTESTED: each directory handle stays open until the entries below the directory are done, and a directory is
        // walked only when the handle held is the entry first opened, so that no path below it can be redirected while
        // the walk runs.
        // Tests check that a held directory can't be renamed and that a link isn't followed, not when the walk closes a
        // handle or a directory swapped between the two opens.
        // When changing how the walk opens or closes a directory, keep each handle open that long and keep the check.
        foreach (string entry in Directory.GetFileSystemEntries(path))
        {
            // The entry is opened with rights that take no part in sharing checks, so that another process using a
            // file doesn't fail the walk, then opened again with the rights its kind needs.
            using SafeFileHandle handle = OpenUnlessNotFound(
                () => Open(entry, WinAPI.READ_CONTROL | WinAPI.FILE_READ_ATTRIBUTES, AnyShare), entry, logger);

            if (handle is null)
            {
                continue;
            }

            DataFolderRefusal refusal = CheckOwner(handle, entry, isTrusted, logger);

            if (refusal is not null)
            {
                return refusal;
            }

            WinAPI.BY_HANDLE_FILE_INFORMATION information = GetInformation(handle);
            bool isReparsePoint = (information.dwFileAttributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            bool isDirectory = (information.dwFileAttributes & WinAPI.FILE_ATTRIBUTE_DIRECTORY) != 0;
            uint access = removeLocalService ? WinAPI.READ_CONTROL | WinAPI.WRITE_DAC : 0;

            if (isReparsePoint && isDirectory)
            {
                if (removeLocalService)
                {
                    // ReOpenFile refuses a directory, so the link is opened again through its path, itself rather than
                    // its target, and compared with the entry first opened; nothing below it is reached.
                    using SafeFileHandle link = OpenUnlessNotFound(
                        () => Open(entry, access | WinAPI.FILE_READ_ATTRIBUTES, AnyShare), entry, logger);

                    if (link is null)
                    {
                        continue;
                    }

                    if (!IsSameEntry(information, GetInformation(link)))
                    {
                        throw new IOException($"{entry} changed while LOCAL SERVICE was being removed from it");
                    }

                    RemoveLocalService(link, entry, logger);
                }

                logger.Log($"did not follow {entry}: it is a reparse point");
            }
            else if (isDirectory)
            {
                // ReOpenFile refuses a directory, so the directory is held through its path, which the directories held
                // above pin, and compared with the entry first opened.
                // The agent keeps running during a feature change, and before a major upgrade stops it, and holds
                // identity without sharing for a moment around each state write, which Hold waits out; a directory held
                // longer than Hold retries fails the hold, and so the run, which can be repeated.
                using SafeFileHandle child = OpenUnlessNotFound(() => Hold(entry, access), entry, logger);

                if (child is null)
                {
                    continue;
                }

                WinAPI.BY_HANDLE_FILE_INFORMATION held = GetInformation(child);

                if (!IsSameEntry(information, held) || !IsPlainDirectory(held.dwFileAttributes))
                {
                    throw new IOException($"{entry} changed while the entries below the data folder were being walked");
                }

                if (removeLocalService)
                {
                    RemoveLocalService(child, entry, logger);
                }

                refusal = WalkBelow(entry, removeLocalService, isTrusted, logger);

                if (refusal is not null)
                {
                    return refusal;
                }
            }
            else
            {
                if (removeLocalService)
                {
                    // UNTESTED: a file symbolic link loses LOCAL SERVICE from its own DACL, not from its target's,
                    // because the first handle opened the link itself and the reopened handle addresses the same object.
                    // Creating a file symbolic link needs elevation or developer mode, which tests don't have.
                    // When changing this, keep opening the entry with FILE_FLAG_OPEN_REPARSE_POINT before reopening it.
                    using SafeFileHandle file = OpenUnlessNotFound(() => Reopen(handle, access, AnyShare), entry, logger);

                    if (file is null)
                    {
                        continue;
                    }

                    RemoveLocalService(file, entry, logger);
                }

                if (isReparsePoint)
                {
                    logger.Log($"did not follow {entry}: it is a reparse point");
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Refuses the entry <paramref name="handle"/> holds, opened from <paramref name="path"/> with <c>READ_CONTROL</c>,
    /// unless <paramref name="isTrusted"/> accepts its owner, who can always change its DACL.
    /// </summary>
    private static DataFolderRefusal CheckOwner(
        SafeFileHandle handle, string path, Func<string, SecurityIdentifier, bool> isTrusted, ILogger logger)
    {
        SecurityIdentifier owner =
            new RawSecurityDescriptor(ReadDescriptor(handle, WinAPI.OWNER_SECURITY_INFORMATION), 0).Owner;

        if (owner is null)
        {
            logger.Log($"refused {path}: it has no owner");
            return new DataFolderRefusal(path, DataFolderProblem.Unreadable);
        }

        if (isTrusted(path, owner))
        {
            return null;
        }

        logger.Log($"refused {path}: it is owned by {owner}");
        return new DataFolderRefusal(path, DataFolderProblem.EntryOwner, owner);
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names with <paramref name="open"/>, or logs that it is skipped when it
    /// can't be found by that name, the name its directory listed it under.
    /// </summary>
    /// <returns>The open entry, or <c>null</c> when it can't be found.</returns>
    /// <exception cref="IOException">
    /// The entry can't be opened for another reason, which the exception wraps, with its path, because the installer log
    /// is all an administrator has to find it.
    /// </exception>
    private static SafeFileHandle OpenUnlessNotFound(Func<SafeFileHandle> open, string path, ILogger logger)
    {
        // UNTESTED: a directory that can't be found when it is held, after its first open succeeded, is skipped, and
        // every other failure to open an entry, such as a sharing violation or a denied access, still fails the walk, so
        // that an entry the walk could change never keeps LOCAL SERVICE unreported.
        // Tests check an entry that can't be found at its first open and a directory held without sharing, not one
        // deleted between the two opens, which can't be timed without a hook in the walk, nor a denied access.
        // When changing this, keep catching only the errors IsNotFound accepts.
        try
        {
            return open();
        }
        catch (Win32Exception e) when (IsNotFound(e))
        {
            logger.Log($"skipped {path}: it can't be found by the name it was listed under");
            return null;
        }
        catch (Exception e)
        {
            logger.Log($"failed to open {path}: {e.Message}");
            throw new IOException($"can't open {path}: {e.Message}", e);
        }
    }

    /// <summary>
    /// Removes each allow entry for LOCAL SERVICE from the DACL of the entry <paramref name="handle"/> holds, opened
    /// from <paramref name="path"/>, keeping its other entries in their order and its control flags, such as its
    /// protection and its auto-inherited mark.
    /// </summary>
    /// <remarks>
    /// A DACL without such an entry isn't written.
    /// </remarks>
    private static void RemoveLocalService(SafeFileHandle handle, string path, ILogger logger)
    {
        RawSecurityDescriptor current = new(ReadDescriptor(handle, WinAPI.DACL_SECURITY_INFORMATION), 0);
        RawAcl dacl = current.DiscretionaryAcl;

        if (dacl is null || !dacl.Cast<GenericAce>().Any(AllowsLocalService))
        {
            return;
        }

        RawAcl remaining = new(dacl.Revision, dacl.Count);

        foreach (GenericAce ace in dacl)
        {
            if (!AllowsLocalService(ace))
            {
                remaining.InsertAce(remaining.Count, ace);
            }
        }

        RawSecurityDescriptor updated = new(current.ControlFlags, null, null, null, remaining);
        byte[] binary = new byte[updated.BinaryLength];
        updated.GetBinaryForm(binary, 0);
        GCHandle pinned = GCHandle.Alloc(binary, GCHandleType.Pinned);

        try
        {
            IntPtr pointer = pinned.AddrOfPinnedObject();

            // Without this request, the file system stores the DACL without marking it auto-inherited.
            if ((current.ControlFlags & ControlFlags.DiscretionaryAclAutoInherited) != 0
                && !WinAPI.SetSecurityDescriptorControl(
                    pointer, WinAPI.SE_DACL_AUTO_INHERIT_REQ, WinAPI.SE_DACL_AUTO_INHERIT_REQ))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!WinAPI.SetKernelObjectSecurity(handle, WinAPI.DACL_SECURITY_INFORMATION, pointer))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            pinned.Free();
        }

        logger.Log($"removed LOCAL SERVICE from the DACL of {path}");
    }

    /// <summary>
    /// Whether <paramref name="ace"/> allows LOCAL SERVICE any access.
    /// </summary>
    private static bool AllowsLocalService(GenericAce ace) =>
        ace is QualifiedAce qualified
        && qualified.AceQualifier == AceQualifier.AccessAllowed
        && qualified.SecurityIdentifier == LocalService;

    /// <summary>
    /// The parts <paramref name="information"/> names of the security descriptor of the entry <paramref name="handle"/>
    /// holds, in self-relative form.
    /// </summary>
    private static byte[] ReadDescriptor(SafeFileHandle handle, uint information)
    {
        // The first call only reports the size the second needs.
        WinAPI.GetKernelObjectSecurity(handle, information, null, 0, out uint size);
        int error = Marshal.GetLastWin32Error();

        if (size == 0)
        {
            throw new Win32Exception(error);
        }

        byte[] descriptor = new byte[size];

        if (!WinAPI.GetKernelObjectSecurity(handle, information, descriptor, size, out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return descriptor;
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target.
    /// </summary>
    private static SafeFileHandle Open(string path, uint access, uint share)
    {
        SafeFileHandle handle = WinAPI.CreateFile(
            path,
            access,
            share,
            IntPtr.Zero,
            WinAPI.OPEN_EXISTING,
            WinAPI.FILE_FLAG_BACKUP_SEMANTICS | WinAPI.FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }

        return handle;
    }

    /// <summary>
    /// Opens the entry <paramref name="handle"/> holds again, a link itself rather than its target, with
    /// <paramref name="access"/> and <paramref name="share"/>.
    /// </summary>
    private static SafeFileHandle Reopen(SafeFileHandle handle, uint access, uint share)
    {
        SafeFileHandle reopened = WinAPI.ReOpenFile(
            handle, access, share, WinAPI.FILE_FLAG_BACKUP_SEMANTICS | WinAPI.FILE_FLAG_OPEN_REPARSE_POINT);

        if (reopened.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            reopened.Dispose();
            throw new Win32Exception(error);
        }

        return reopened;
    }

    private static uint GetAttributes(SafeFileHandle handle) => GetInformation(handle).dwFileAttributes;

    private static WinAPI.BY_HANDLE_FILE_INFORMATION GetInformation(SafeFileHandle handle)
    {
        if (!WinAPI.GetFileInformationByHandle(handle, out WinAPI.BY_HANDLE_FILE_INFORMATION information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return information;
    }

    private static bool IsSameEntry(WinAPI.BY_HANDLE_FILE_INFORMATION a, WinAPI.BY_HANDLE_FILE_INFORMATION b) =>
        a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
        && a.nFileIndexHigh == b.nFileIndexHigh
        && a.nFileIndexLow == b.nFileIndexLow;

    private static bool IsPlainDirectory(uint attributes) =>
        (attributes & WinAPI.FILE_ATTRIBUTE_DIRECTORY) != 0 && (attributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) == 0;

    internal static bool IsNotFound(Win32Exception e) =>
        e.NativeErrorCode is WinAPI.ERROR_FILE_NOT_FOUND or WinAPI.ERROR_PATH_NOT_FOUND;

    /// <summary>
    /// The groups Authz resolves for <paramref name="sid"/>, nested and domain groups included.
    /// </summary>
    private static List<SecurityIdentifier> AuthzGroups(SecurityIdentifier sid)
    {
        if (!WinAPI.AuthzInitializeResourceManager(
                WinAPI.AUTHZ_RM_FLAG_NO_AUDIT, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, null, out IntPtr manager))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            byte[] binary = new byte[sid.BinaryLength];
            sid.GetBinaryForm(binary, 0);

            if (!WinAPI.AuthzInitializeContextFromSid(
                    0, binary, manager, IntPtr.Zero, default, IntPtr.Zero, out IntPtr context))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                // The first call only reports the size the second needs.
                WinAPI.AuthzGetInformationFromContext(
                    context, WinAPI.AuthzContextInfoGroupsSids, 0, out uint size, IntPtr.Zero);
                int error = Marshal.GetLastWin32Error();
                int offset = Marshal.OffsetOf<WinAPI.TOKEN_GROUPS>(nameof(WinAPI.TOKEN_GROUPS.Groups)).ToInt32();

                if (size < offset)
                {
                    throw new Win32Exception(error);
                }

                IntPtr buffer = Marshal.AllocHGlobal((int)size);

                try
                {
                    if (!WinAPI.AuthzGetInformationFromContext(
                            context, WinAPI.AuthzContextInfoGroupsSids, size, out size, buffer))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    int count = Marshal.ReadInt32(buffer);
                    int stride = Marshal.SizeOf<WinAPI.SID_AND_ATTRIBUTES>();

                    if (count < 0 || offset + (long)count * stride > size)
                    {
                        throw new InvalidDataException("Authz returned a group list larger than its buffer");
                    }

                    return Enumerable.Range(0, count)
                        .Select(i => new SecurityIdentifier(Marshal.ReadIntPtr(buffer, offset + i * stride)))
                        .ToList();
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                WinAPI.AuthzFreeContext(context);
            }
        }
        finally
        {
            WinAPI.AuthzFreeResourceManager(manager);
        }
    }

    /// <summary>
    /// The direct members of the local Administrators group.
    /// </summary>
    private static List<SecurityIdentifier> LocalAdministrators()
    {
        // NetLocalGroupGetMembers takes the group's name, which is localized, without its BUILTIN domain.
        string name = Administrators.Translate(typeof(NTAccount)).Value;
        name = name.Substring(name.LastIndexOf('\\') + 1);

        uint status = WinAPI.NetLocalGroupGetMembers(
            null, name, 0, out IntPtr buffer, WinAPI.MAX_PREFERRED_LENGTH, out uint read, out _, IntPtr.Zero);

        if (status != WinAPI.NERR_Success)
        {
            throw new Win32Exception((int)status);
        }

        try
        {
            // Level 0 returns LOCALGROUP_MEMBERS_INFO_0 entries, each a single SID pointer.
            return Enumerable.Range(0, (int)read)
                .Select(i => new SecurityIdentifier(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)))
                .ToList();
        }
        finally
        {
            WinAPI.NetApiBufferFree(buffer);
        }
    }

    /// <summary>
    /// A security descriptor converted from SDDL, freed on disposal.
    /// </summary>
    private sealed class SecurityDescriptor : IDisposable
    {
        internal IntPtr Pointer { get; }

        internal SecurityDescriptor(string sddl)
        {
            const uint sdRevision = 1;

            if (!WinAPI.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, sdRevision, out IntPtr pointer, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            this.Pointer = pointer;
        }

        public void Dispose() => WinAPI.LocalFree(this.Pointer);
    }
}
