using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

[assembly: InternalsVisibleTo("DevolutionsGateway.Installer.Tests")]

namespace DevolutionsGateway.Actions;

/// <summary>
/// Directory and file operations that act on the entry a path names, never on the target of a link at that path.
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

    private const uint OwnerAndDacl = WinAPI.OWNER_SECURITY_INFORMATION | WinAPI.DACL_SECURITY_INFORMATION;

    private const uint OwnerGroupAndDacl = OwnerAndDacl | WinAPI.GROUP_SECURITY_INFORMATION;

    /// <summary>
    /// Creates the directory <paramref name="path"/> with the security descriptor <paramref name="sddl"/>, so that it
    /// never exists with the DACL it would inherit from its parent, or with the security it inherits when
    /// <paramref name="sddl"/> is <c>null</c>.
    /// </summary>
    /// <returns><c>false</c> when an entry named <paramref name="path"/> already exists, which is left unchanged.</returns>
    internal static bool Create(string path, string sddl)
    {
        using SecurityDescriptor descriptor = sddl is null ? null : new(sddl);
        bool autoInherited = descriptor is not null && RequestAutoInherit(descriptor, sddl);
        WinAPI.SECURITY_ATTRIBUTES attributes = new()
        {
            nLength = (uint)Marshal.SizeOf<WinAPI.SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor = descriptor?.Pointer ?? IntPtr.Zero,
        };

        if (WinAPI.CreateDirectory(path, ref attributes))
        {
            // CreateDirectory stores the DACL without marking it auto-inherited, even with SE_DACL_AUTO_INHERIT_REQ set,
            // so the DACL is set again through the new directory's handle; until then, the directory has the same
            // entries without the mark.
            // The handle doesn't hold the directory, because the check and the set both act on the entry it opened.
            if (autoInherited)
            {
                using SafeFileHandle handle = Open(
                    path, WinAPI.READ_CONTROL | WinAPI.WRITE_DAC | WinAPI.FILE_READ_ATTRIBUTES, AnyShare);

                if (!IsPlainDirectory(GetInformation(handle).dwFileAttributes))
                {
                    throw new IOException($"{path} changed while it was being created");
                }

                if (!WinAPI.SetKernelObjectSecurity(handle, WinAPI.DACL_SECURITY_INFORMATION, descriptor.Pointer))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

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
    /// Sets the owner and the DACL of the file
    /// <c><paramref name="root"/>\<paramref name="names"/>[0]\…\<paramref name="names"/>[n-1]</c> to those of
    /// <paramref name="sddl"/>, without following any link.
    /// </summary>
    /// <remarks>
    /// A file with more than one hard link is refused, because its security is shared with every other name of the
    /// file, which may be outside the directories checked.
    /// </remarks>
    /// <exception cref="IOException">
    /// An entry above the file is a reparse point or not a directory, or the file is a reparse point, a directory or a
    /// file with more than one hard link.
    /// </exception>
    /// <exception cref="Win32Exception">The file or a directory above it doesn't exist, or can't be opened.</exception>
    internal static void SetFileSecurity(string root, string[] names, string sddl)
    {
        List<SafeFileHandle> parents = new();

        try
        {
            string target = Path.Combine(HoldParents(root, names, parents), names[names.Length - 1]);
            using SafeFileHandle handle = OpenToSetSecurity(target);
            WinAPI.BY_HANDLE_FILE_INFORMATION information = GetInformation(handle);

            const uint notAFile = WinAPI.FILE_ATTRIBUTE_REPARSE_POINT | WinAPI.FILE_ATTRIBUTE_DIRECTORY;

            if ((information.dwFileAttributes & notAFile) != 0)
            {
                throw new IOException($"{target} is a reparse point or not a file");
            }

            if (information.nNumberOfLinks > 1)
            {
                throw new IOException($"{target} has {information.nNumberOfLinks} hard links");
            }

            Apply(handle, sddl);
        }
        finally
        {
            parents.ForEach(parent => parent.Dispose());
        }
    }

    /// <summary>
    /// Sets the owner and the DACL of the directory <paramref name="directory"/> holds, opened from
    /// <paramref name="path"/> by <see cref="HoldToSetSecurity"/>, to those of <paramref name="sddl"/>, then resets the
    /// security of the files and directories below it, without following any link.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A file gets an unprotected DACL made of its explicit entries and the entries it inherits from the directory that
    /// holds it: what <c>SetNamedSecurityInfo</c> computes when it removes the file's DACL protection.
    /// An unprotected directory gets its explicit entries and the entries it inherits, as when Windows passes a new
    /// DACL on, and a protected directory keeps its DACL, since an administrator protected it on purpose.
    /// An entry gets the entries its directory now passes on, and loses the ones the directory passed on before: an
    /// entry whose DACL isn't marked auto-inherited holds what it inherited as explicit entries, which are told apart
    /// by comparing them with what its directory passed on before the change, as Windows does.
    /// The inherited entries are computed from the security read through the directory handle held, rather than by
    /// <c>SetSecurityInfo</c>, which reads the parent's security through a path it resolves again, and written through
    /// the entry's handle.
    /// A directory gets its DACL before the entries below it, which inherit from its new DACL.
    /// </para>
    /// <para>
    /// Every allow entry for LOCAL SERVICE is removed below the directory, explicit or inherited, in a protected
    /// directory too, so that none is left when <paramref name="sddl"/> has none: only SYSTEM, administrators and the
    /// service account may change what the Gateway stores there,
    /// and earlier installers gave LOCAL SERVICE write access, which a protected directory or a DACL not marked
    /// auto-inherited holds as explicit entries.
    /// The installer doesn't accept LOCAL SERVICE as the service account, so this never removes the service account's
    /// access.
    /// </para>
    /// <para>
    /// Each directory is held while the entries below it are opened, so no path below it can be redirected.
    /// A reparse point, such as a junction or a symbolic link, is neither followed nor changed, and a file with more
    /// than one hard link is skipped, because its security is shared with every other name of the file, which may be
    /// outside the tree.
    /// A directory replaced while the walk reaches it fails the walk.
    /// </para>
    /// </remarks>
    /// <param name="kept">
    /// The names of the entries directly below the directory whose security is left as it is, because another step
    /// sets it.
    /// </param>
    /// <exception cref="IOException">The directory is a reparse point or not a directory.</exception>
    internal static void SetSecurityAndInheritBelow(
        SafeFileHandle directory, string path, string sddl, string[] kept, ILogger logger)
    {
        if (!IsPlainDirectory(GetInformation(directory).dwFileAttributes))
        {
            throw new IOException($"{path} is a reparse point or not a directory");
        }

        byte[] previous = ReadDescriptor(directory, OwnerGroupAndDacl);
        Apply(directory, sddl);

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        InheritBelow(directory, path, previous, kept, identity.Token, logger);
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target, to read its security and to
    /// set it.
    /// </summary>
    private static SafeFileHandle OpenToSetSecurity(string path) =>
        Open(
            path,
            WinAPI.READ_CONTROL | WinAPI.WRITE_DAC | WinAPI.WRITE_OWNER | WinAPI.FILE_READ_ATTRIBUTES,
            AnyShare);

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target, to read its security and to
    /// set it with <see cref="SetSecurityAndInheritBelow"/>, holding it as
    /// <see cref="Hold"/> does.
    /// </summary>
    internal static SafeFileHandle HoldToSetSecurity(string path) =>
        Hold(path, WinAPI.READ_CONTROL | WinAPI.WRITE_DAC | WinAPI.WRITE_OWNER);

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
        uint attributes = GetInformation(handle).dwFileAttributes;
        bool isReparsePoint = (attributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        bool isDirectory = (attributes & WinAPI.FILE_ATTRIBUTE_DIRECTORY) != 0;

        return (new RawSecurityDescriptor(ReadDescriptor(handle, OwnerAndDacl), 0), isReparsePoint, isDirectory);
    }

    /// <summary>
    /// Whether <paramref name="sid"/> is SYSTEM, Administrators or TrustedInstaller.
    /// </summary>
    internal static bool IsPrivileged(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid == Administrators || sid == TrustedInstaller;

    /// <summary>
    /// Whether <paramref name="owner"/> may own the Gateway's data: SYSTEM, Administrators, TrustedInstaller, or a
    /// member of Administrators.
    /// </summary>
    /// <remarks>
    /// Membership is decided as the Devolutions Agent and its installer decide it (<c>owner_is_administrator_member</c>
    /// in <c>crates/agent-identity/src/windows.rs</c>), so that both installers accept the same owners of the
    /// <c>Devolutions</c> folder they share: by the groups Authz resolves for the owner or, when Authz fails, by the
    /// local member list of Administrators.
    /// </remarks>
    /// <exception cref="Win32Exception">Authz failed and the local member list of Administrators can't be read.</exception>
    internal static bool IsTrustedOwner(SecurityIdentifier owner, ILogger logger)
    {
        if (IsPrivileged(owner))
        {
            return true;
        }

        // UNTESTED: a member of Administrators, such as an administrator's user account, is trusted through the groups
        // Authz resolves or, when Authz fails, as it may for a domain account, through the local member list.
        // No test runs with such an account, and this keeps both installers accepting the same owners.
        // When changing this, keep it in line with owner_is_administrator_member in crates/agent-identity/src/windows.rs.
        List<SecurityIdentifier> groups;

        try
        {
            groups = AuthzGroups(owner);
        }
        catch (Exception e)
        {
            logger.Log($"failed to resolve the groups of {owner}, checking the local members of Administrators: {e}");
            return LocalAdministrators().Contains(owner);
        }

        return groups.Contains(Administrators);
    }

    internal static bool IsNotFound(Win32Exception e) =>
        e.NativeErrorCode is WinAPI.ERROR_FILE_NOT_FOUND or WinAPI.ERROR_PATH_NOT_FOUND;

    /// <summary>
    /// Holds each directory <c><paramref name="root"/>\<paramref name="names"/>[0]</c> to
    /// <c><paramref name="root"/>\<paramref name="names"/>[0]\…\<paramref name="names"/>[n-2]</c> in
    /// <paramref name="held"/>, which the caller disposes.
    /// </summary>
    /// <returns>The path of the last directory held, or <paramref name="root"/> when there is one name.</returns>
    /// <exception cref="IOException">An entry on the path is a reparse point or not a directory.</exception>
    private static string HoldParents(string root, string[] names, List<SafeFileHandle> held)
    {
        string path = root;

        foreach (string name in names.Take(names.Length - 1))
        {
            path = Path.Combine(path, name);
            SafeFileHandle parent = Hold(path);
            held.Add(parent);

            if (!IsPlainDirectory(GetInformation(parent).dwFileAttributes))
            {
                throw new IOException($"{path} is a reparse point or not a directory");
            }
        }

        return path;
    }

    /// <summary>
    /// Resets the security of each entry below the directory <paramref name="directory"/> holds, opened from
    /// <paramref name="path"/> by <see cref="Hold"/> with <c>READ_CONTROL</c>, but those named in
    /// <paramref name="kept"/>, as <see cref="SetSecurityAndInheritBelow"/> describes, given the security descriptor
    /// <paramref name="previous"/> the directory had before its DACL changed.
    /// </summary>
    private static void InheritBelow(
        SafeFileHandle directory, string path, byte[] previous, string[] kept, IntPtr token, ILogger logger)
    {
        byte[] parent = ReadDescriptor(directory, OwnerGroupAndDacl);

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

            if (kept.Contains(Path.GetFileName(entry), StringComparer.OrdinalIgnoreCase))
            {
                logger.Log($"kept the security of {entry}: another step sets it");
            }
            else if ((information.dwFileAttributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
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
                    throw new IOException($"{entry} changed while its security was being reset");
                }

                byte[] before = ReadDescriptor(child, OwnerGroupAndDacl);

                if ((new RawSecurityDescriptor(before, 0).ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0)
                {
                    RemoveLocalService(child);
                }
                else
                {
                    Inherit(child, parent, previous, isDirectory: true, token);
                }

                InheritBelow(child, entry, before, [], token, logger);
            }
            else if (information.nNumberOfLinks > 1)
            {
                logger.Log($"kept the security of {entry}: it has {information.nNumberOfLinks} hard links");
            }
            else
            {
                using SafeFileHandle file = Reopen(handle, WinAPI.READ_CONTROL | WinAPI.WRITE_DAC, AnyShare);
                Inherit(file, parent, previous, isDirectory: false, token);
            }
        }
    }

    /// <summary>
    /// Replaces the DACL of the file or directory <paramref name="entry"/> holds by an unprotected one made of its
    /// explicit entries and the entries it inherits from the security descriptor <paramref name="parent"/> of its
    /// directory, which had the security descriptor <paramref name="previous"/> when the entry got its DACL.
    /// </summary>
    private static void Inherit(SafeFileHandle entry, byte[] parent, byte[] previous, bool isDirectory, IntPtr token)
    {
        WinAPI.GENERIC_MAPPING mapping = WinAPI.FileGenericMapping;
        byte[] descriptor = ReadDescriptor(entry, OwnerGroupAndDacl);
        RawSecurityDescriptor current = new(descriptor, 0);

        // A DACL not marked auto-inherited holds the entries it inherited as explicit ones, as an entry created in a
        // folder whose DACL isn't marked auto-inherited does, so these are told apart by comparing them with what the
        // parent passed on before its DACL changed, as Windows does when it passes a new DACL on.
        if ((current.ControlFlags & ControlFlags.DiscretionaryAclAutoInherited) == 0)
        {
            if (!WinAPI.ConvertToAutoInheritPrivateObjectSecurity(
                    previous, descriptor, out IntPtr converted, IntPtr.Zero, isDirectory, ref mapping))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                current = ToRaw(converted);
            }
            finally
            {
                WinAPI.DestroyPrivateObjectSecurity(ref converted);
            }
        }

        RawAcl explicitEntries = null;

        if (current.DiscretionaryAcl is not null)
        {
            explicitEntries = new RawAcl(current.DiscretionaryAcl.Revision, current.DiscretionaryAcl.Count);

            foreach (GenericAce ace in current.DiscretionaryAcl)
            {
                if ((ace.AceFlags & AceFlags.Inherited) == 0 && !AllowsLocalService(ace))
                {
                    explicitEntries.InsertAce(explicitEntries.Count, ace);
                }
            }
        }

        // An unprotected, auto-inherited creator DACL with only the explicit entries, so that the new DACL keeps them,
        // and adds the entries the parent passes on to an entry of its kind, as Windows does when a DACL's protection
        // is removed.
        RawSecurityDescriptor unprotected = new(
            (current.ControlFlags & ~ControlFlags.DiscretionaryAclProtected) | ControlFlags.DiscretionaryAclAutoInherited,
            current.Owner,
            current.Group,
            null,
            explicitEntries);
        byte[] creator = new byte[unprotected.BinaryLength];
        unprotected.GetBinaryForm(creator, 0);

        if (!WinAPI.CreatePrivateObjectSecurityEx(
                parent,
                creator,
                out IntPtr computed,
                IntPtr.Zero,
                isDirectory,
                WinAPI.SEF_DACL_AUTO_INHERIT | WinAPI.SEF_AVOID_OWNER_CHECK | WinAPI.SEF_AVOID_PRIVILEGE_CHECK,
                token,
                ref mapping))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            // Without this request, the file system stores the DACL without marking it auto-inherited.
            if (!WinAPI.SetSecurityDescriptorControl(
                    computed, WinAPI.SE_DACL_AUTO_INHERIT_REQ, WinAPI.SE_DACL_AUTO_INHERIT_REQ))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!WinAPI.SetKernelObjectSecurity(entry, WinAPI.DACL_SECURITY_INFORMATION, computed))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            WinAPI.DestroyPrivateObjectSecurity(ref computed);
        }
    }

    /// <summary>
    /// Removes each allow entry for LOCAL SERVICE from the DACL of the entry <paramref name="handle"/> holds, keeping
    /// its other entries and its control flags, such as its protection.
    /// </summary>
    private static void RemoveLocalService(SafeFileHandle handle)
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
    }

    /// <summary>
    /// Whether <paramref name="ace"/> allows LOCAL SERVICE any access.
    /// </summary>
    private static bool AllowsLocalService(GenericAce ace) =>
        ace is QualifiedAce qualified
        && qualified.AceQualifier == AceQualifier.AccessAllowed
        && qualified.SecurityIdentifier == LocalService;

    /// <summary>
    /// The self-relative security descriptor at <paramref name="descriptor"/>, copied.
    /// </summary>
    private static RawSecurityDescriptor ToRaw(IntPtr descriptor)
    {
        byte[] binary = new byte[WinAPI.GetSecurityDescriptorLength(descriptor)];
        Marshal.Copy(descriptor, binary, 0, binary.Length);
        return new RawSecurityDescriptor(binary, 0);
    }

    /// <summary>
    /// Sets the owner and the DACL of the entry <paramref name="handle"/> holds to those of <paramref name="sddl"/>.
    /// </summary>
    private static void Apply(SafeFileHandle handle, string sddl)
    {
        using SecurityDescriptor descriptor = new(sddl);
        RequestAutoInherit(descriptor, sddl);

        if (!WinAPI.SetKernelObjectSecurity(handle, OwnerAndDacl, descriptor.Pointer))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    /// <summary>
    /// Asks the file system to store the DACL of <paramref name="descriptor"/> marked auto-inherited when
    /// <paramref name="sddl"/>, its source, marks it so.
    /// </summary>
    /// <remarks>
    /// Without this request, setting the DACL stores it without the mark, and the entries created below then hold what
    /// they inherit as explicit entries.
    /// </remarks>
    /// <returns>Whether the mark was requested.</returns>
    private static bool RequestAutoInherit(SecurityDescriptor descriptor, string sddl)
    {
        if ((new RawSecurityDescriptor(sddl).ControlFlags & ControlFlags.DiscretionaryAclAutoInherited) == 0)
        {
            return false;
        }

        if (!WinAPI.SetSecurityDescriptorControl(
                descriptor.Pointer, WinAPI.SE_DACL_AUTO_INHERIT_REQ, WinAPI.SE_DACL_AUTO_INHERIT_REQ))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return true;
    }

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
