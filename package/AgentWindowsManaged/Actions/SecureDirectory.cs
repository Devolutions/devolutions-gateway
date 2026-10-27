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

    /// <summary>
    /// NT SERVICE\TrustedInstaller, the Windows Modules Installer service.
    /// </summary>
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    // UNTESTED: the deletion holds each directory handle, without FILE_SHARE_DELETE, until the entries below the
    // directory are done.
    // Renaming or replacing a directory needs delete access to it, so no path below a held directory can be redirected
    // to another folder.
    // When changing how the deletion opens or closes a directory, keep this share mode and keep the handle open that long.
    private static readonly uint HeldShare = WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE;

    private static readonly uint AnyShare = WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE | WinAPI.FILE_SHARE_DELETE;

    /// <summary>
    /// Creates the directory <paramref name="path"/> with the security descriptor <paramref name="sddl"/>, so that it
    /// never exists with the DACL it would inherit from its parent.
    /// </summary>
    /// <returns><c>false</c> when an entry named <paramref name="path"/> already exists, which is left unchanged.</returns>
    internal static bool Create(string path, string sddl)
    {
        using SecurityDescriptor descriptor = new(sddl);
        WinAPI.SECURITY_ATTRIBUTES attributes = new()
        {
            nLength = (uint)Marshal.SizeOf<WinAPI.SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = descriptor.Pointer,
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
    /// Sets the owner and the DACL of the directory <paramref name="path"/> to those of <paramref name="sddl"/>.
    /// </summary>
    /// <remarks>
    /// Only the directory changes: unlike <c>SetSecurityInfo</c>, this doesn't propagate inheritable entries to existing
    /// children, so the entries below keep the security they have.
    /// </remarks>
    /// <exception cref="IOException"><paramref name="path"/> is a reparse point or not a directory.</exception>
    internal static void SetSecurity(string path, string sddl)
    {
        using SafeFileHandle handle = Open(
            path, WinAPI.WRITE_DAC | WinAPI.WRITE_OWNER | WinAPI.FILE_READ_ATTRIBUTES, AnyShare);

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
    /// <param name="hold">
    /// Whether to deny delete sharing, so that the entry can't be renamed or replaced while the handle is open.
    /// </param>
    internal static SafeFileHandle OpenToRead(string path, bool hold) =>
        Open(path, WinAPI.READ_CONTROL | WinAPI.FILE_READ_ATTRIBUTES, hold ? HeldShare : AnyShare);

    /// <summary>
    /// The owner and the DACL of the entry <paramref name="handle"/> holds, and whether that entry is a reparse point.
    /// </summary>
    internal static (RawSecurityDescriptor Security, bool IsReparsePoint) ReadSecurity(SafeFileHandle handle)
    {
        bool isReparsePoint = (GetAttributes(handle) & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        const uint information = WinAPI.OWNER_SECURITY_INFORMATION | WinAPI.DACL_SECURITY_INFORMATION;

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

        return (new RawSecurityDescriptor(descriptor, 0), isReparsePoint);
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
        List<SafeFileHandle> handles = new();

        try
        {
            string path = root;

            foreach (string name in names.Take(names.Length - 1))
            {
                path = Path.Combine(path, name);
                SafeFileHandle parent = Open(path, WinAPI.FILE_READ_ATTRIBUTES, HeldShare);
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

    private static uint GetAttributes(SafeFileHandle handle)
    {
        if (!WinAPI.GetFileInformationByHandle(handle, out WinAPI.BY_HANDLE_FILE_INFORMATION information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return information.dwFileAttributes;
    }

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
