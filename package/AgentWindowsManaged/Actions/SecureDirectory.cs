using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

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
    /// allow entry for LOCAL SERVICE from the DACL of every file and directory below it, without following any link.
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
    /// Each directory is held while the entries below it are opened, so no path below it can be redirected.
    /// A reparse point, such as a junction or a symbolic link, is neither followed nor changed, and a file with more
    /// than one hard link is skipped, because its security is shared with every other name of the file, which may be
    /// outside the tree.
    /// A directory replaced while the walk reaches it fails the walk.
    /// </para>
    /// </remarks>
    /// <exception cref="IOException">The directory is a reparse point or not a directory.</exception>
    internal static void SetSecurityAndRemoveLocalServiceBelow(
        SafeFileHandle directory, string path, string sddl, ILogger logger)
    {
        SetSecurity(directory, path, sddl);
        RemoveLocalServiceBelow(path, logger);
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
    /// </remarks>
    internal static SafeFileHandle Hold(string path, uint access = 0) =>
        Open(path, access | WinAPI.FILE_TRAVERSE | WinAPI.FILE_READ_ATTRIBUTES, HeldShare);

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
    /// Removes each allow entry for LOCAL SERVICE from the DACL of every file and directory below the directory
    /// <paramref name="path"/>, which the caller holds, as <see cref="SetSecurityAndRemoveLocalServiceBelow"/> describes.
    /// </summary>
    private static void RemoveLocalServiceBelow(string path, ILogger logger)
    {
        // UNTESTED: each directory handle stays open until the entries below the directory are done, and a directory is
        // walked only when the handle held is the entry first opened, so that no path below it can be redirected while
        // the walk runs.
        // Tests check that a held directory can't be renamed and that a link isn't followed, not when the walk closes a
        // handle or a directory swapped between the two opens.
        // When changing how the walk opens or closes a directory, keep each handle open that long and keep the check.
        foreach (string entry in Directory.GetFileSystemEntries(path))
        {
            // The entry is opened with a right that takes no part in sharing checks, so that another process using a
            // file doesn't fail the walk, then opened again with the rights its kind needs.
            using SafeFileHandle handle = Open(entry, WinAPI.FILE_READ_ATTRIBUTES, AnyShare);
            WinAPI.BY_HANDLE_FILE_INFORMATION information = GetInformation(handle);

            if ((information.dwFileAttributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                logger.Log($"kept the security of {entry}: it is a reparse point");
            }
            else if ((information.dwFileAttributes & WinAPI.FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                // ReOpenFile refuses a directory, so the directory is held through its path, which the directories held
                // above pin, and compared with the entry first opened.
                using SafeFileHandle child = Hold(entry, WinAPI.READ_CONTROL | WinAPI.WRITE_DAC);
                WinAPI.BY_HANDLE_FILE_INFORMATION held = GetInformation(child);

                if (!IsSameEntry(information, held) || !IsPlainDirectory(held.dwFileAttributes))
                {
                    throw new IOException($"{entry} changed while LOCAL SERVICE was being removed from it");
                }

                RemoveLocalService(child, entry, logger);
                RemoveLocalServiceBelow(entry, logger);
            }
            else if (information.nNumberOfLinks > 1)
            {
                logger.Log($"kept the security of {entry}: it has {information.nNumberOfLinks} hard links");
            }
            else
            {
                using SafeFileHandle file = Reopen(handle, WinAPI.READ_CONTROL | WinAPI.WRITE_DAC, AnyShare);
                RemoveLocalService(file, entry, logger);
            }
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
