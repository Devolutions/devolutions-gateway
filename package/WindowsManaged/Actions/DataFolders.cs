using DevolutionsGateway.Resources;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DevolutionsGateway.Actions;

/// <summary>
/// Why the installer refuses to use a folder of the Gateway's data path.
/// </summary>
internal enum DataFolderProblem
{
    /// <summary>
    /// The folder is a link, which can point anywhere.
    /// </summary>
    Link,

    /// <summary>
    /// The entry is a file, not a folder.
    /// </summary>
    File,

    /// <summary>
    /// The folder's owner, who can always change its permissions, is not trusted.
    /// </summary>
    Owner,

    /// <summary>
    /// The folder's DACL lets an untrusted account replace the folder or what it contains.
    /// </summary>
    Access,

    /// <summary>
    /// The folder's owner or DACL can't be read.
    /// </summary>
    Unreadable,
}

/// <summary>
/// A folder of the Gateway's data path that the installer refuses to use.
/// </summary>
internal sealed class DataFolderRefusal(string folder, DataFolderProblem problem, SecurityIdentifier account = null)
{
    internal string Folder { get; } = folder;

    internal DataFolderProblem Problem { get; } = problem;

    /// <summary>
    /// The owner of the folder for <see cref="DataFolderProblem.Owner"/>, or the account the offending entry grants for
    /// <see cref="DataFolderProblem.Access"/>.
    /// </summary>
    internal SecurityIdentifier Account { get; } = account;

    /// <summary>
    /// The error the installer shows, in the language whose LCID is <paramref name="productLanguage"/>.
    /// </summary>
    internal string Message(string productLanguage)
    {
        string id = this.Problem switch
        {
            DataFolderProblem.Link => Strings.DataFolderIsLink,
            DataFolderProblem.File => Strings.DataFolderIsFile,
            DataFolderProblem.Owner => Strings.DataFolderOwnedByUntrustedAccount,
            DataFolderProblem.Access => Strings.DataFolderReplaceableByUntrustedAccount,
            DataFolderProblem.Unreadable => Strings.DataFolderSecurityUnreadable,
            _ => throw new ArgumentOutOfRangeException(nameof(this.Problem), this.Problem, null),
        };

        return string.Format(InstallerStrings.Localize(productLanguage, id), this.Folder, AccountName(this.Account));
    }

    /// <summary>
    /// The account name of <paramref name="sid"/>, or its SID string when it has none.
    /// </summary>
    private static string AccountName(SecurityIdentifier sid)
    {
        if (sid is null)
        {
            return null;
        }

        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (Exception)
        {
            return sid.Value;
        }
    }
}

/// <summary>
/// Checks <c>Devolutions</c> and <c>Devolutions\Gateway</c> under ProgramData before the installer uses them.
/// </summary>
/// <remarks>
/// The installer writes the Gateway's data there as SYSTEM, so an account that controls either folder could redirect
/// or replace what the installer and the Gateway write.
/// A folder that doesn't exist yet passes.
/// </remarks>
internal static class DataFolders
{
    private const string Devolutions = "Devolutions";

    private const string Gateway = "Gateway";

    /// <summary>
    /// The rights that let an account delete, rename or replace a folder or an entry in it, or give itself any right.
    /// </summary>
    private const uint ReplaceRights =
        WinAPI.DELETE | WinAPI.WRITE_DAC | WinAPI.WRITE_OWNER | WinAPI.FILE_DELETE_CHILD | WinAPI.GENERIC_ALL;

    /// <summary>
    /// OWNER RIGHTS, whose entry applies to the owner, which is checked on its own.
    /// </summary>
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    /// <summary>
    /// Checks <c>Devolutions</c> and <c>Devolutions\Gateway</c> under <paramref name="root"/> without changing anything.
    /// </summary>
    /// <returns>The first refusal, or <c>null</c> when both folders pass.</returns>
    internal static DataFolderRefusal Check(string root, ILogger logger)
    {
        string devolutions = Path.Combine(root, Devolutions);
        DataFolderRefusal refusal = Inspect(
            devolutions, path => SecureDirectory.OpenToRead(path, hold: true), checkAccess: true, logger,
            out SafeFileHandle handle);

        using (handle)
        {
            if (refusal is not null || handle is null)
            {
                return refusal;
            }

            // UNTESTED: an existing Gateway is refused when it is a link or has an untrusted owner, here and in Create.
            // A test reaches it only below a Devolutions folder that passes, which needs an owner that a test without
            // elevation can't set.
            // When changing this, keep Gateway checked in both, without the DACL rule, as the installer resets its DACL.
            refusal = Inspect(
                Path.Combine(devolutions, Gateway), path => SecureDirectory.OpenToRead(path, hold: false),
                checkAccess: false, logger, out SafeFileHandle gateway);
            gateway?.Dispose();

            return refusal;
        }
    }

    /// <summary>
    /// Creates <c>Devolutions\Gateway</c> under <paramref name="root"/> with the security descriptor
    /// <paramref name="sddl"/>, after checking <c>Devolutions</c>, or checks an existing <c>Gateway</c> and resets its
    /// owner and DACL to those of <paramref name="sddl"/>.
    /// </summary>
    /// <remarks>
    /// A missing <c>Devolutions</c> is created with the DACL it inherits, then checked like an existing one.
    /// <c>Gateway</c> gets its security descriptor when it is created, so that it never exists with the DACL it would
    /// inherit from ProgramData, which lets users add entries.
    /// The entries below an existing <c>Gateway</c> get what it now passes on, and lose what it passed on before, which
    /// only its DACL before the reset tells apart from their explicit entries.
    /// </remarks>
    /// <returns>
    /// The first refusal, in which case nothing is created or changed below <c>Devolutions</c>, or <c>null</c>.
    /// </returns>
    internal static DataFolderRefusal Create(string root, string sddl, ILogger logger)
    {
        string devolutions = Path.Combine(root, Devolutions);
        string gateway = Path.Combine(devolutions, Gateway);

        SecureDirectory.Create(devolutions, sddl: null);

        // UNTESTED: the handle on Devolutions stays open until Gateway is created, or checked and reset, below it, so
        // that this happens in the folder just checked, not in one put at that path afterwards.
        // Tests check that a held folder can't be renamed, not how long this handle stays open.
        // When changing this, keep the handle open until Gateway is done.
        DataFolderRefusal refusal = Inspect(
            devolutions, path => SecureDirectory.OpenToRead(path, hold: true), checkAccess: true, logger,
            out SafeFileHandle handle);

        using (handle)
        {
            if (refusal is not null)
            {
                return refusal;
            }

            if (handle is null)
            {
                throw new IOException($"{devolutions} was deleted after it was created");
            }

            if (SecureDirectory.Create(gateway, sddl))
            {
                logger.Log($"created {gateway}");
                return null;
            }

            refusal = Inspect(
                gateway, SecureDirectory.HoldToSetSecurity, checkAccess: false, logger, out SafeFileHandle existing);

            using (existing)
            {
                if (refusal is not null)
                {
                    return refusal;
                }

                if (existing is null)
                {
                    throw new IOException($"{gateway} was deleted after it was found");
                }

                // UNTESTED: setting the owner to SYSTEM succeeds only for a caller allowed to give an object another
                // owner, as the installer's SYSTEM process is; tests run as a user and set the user as the owner.
                // When changing this, keep resetting the security of an existing Gateway on this handle, so that only
                // the accounts the installer provisions can change what the Gateway stores there.
                // UNTESTED: the entries below an existing Gateway lose what it passed on before only when they are
                // reset here, while its previous DACL can still be read; the security reset run afterwards sees the
                // new DACL as the previous one.
                // Tests check SetSecurityAndInheritBelow, not that an existing Gateway is reset with it here, because
                // the user running them isn't a trusted owner.
                // When changing this, reset the entries below in the same call that changes the DACL of Gateway.
                SecureDirectory.SetSecurityAndInheritBelow(existing, gateway, sddl, logger);
                logger.Log($"reset the owner and the DACL of {gateway} and the entries below it");

                return null;
            }
        }
    }

    /// <summary>
    /// Whether the installer refuses to use <paramref name="folder"/>, given its security descriptor and whether it is a
    /// link.
    /// </summary>
    /// <remarks>
    /// The DACL rule trusts the accounts the owner rule trusts, because an account that may own the folder gains nothing
    /// from an entry it could give itself as the owner, and a <c>Devolutions</c> folder that an administrator's
    /// application created first, without elevation, carries a full-control entry for that administrator.
    /// </remarks>
    /// <param name="checkAccess">
    /// Whether to refuse a DACL that lets an account other than SYSTEM, Administrators, TrustedInstaller, a member of
    /// Administrators or OWNER RIGHTS replace the folder or what it contains.
    /// </param>
    /// <returns>The refusal, or <c>null</c> when the folder passes.</returns>
    internal static DataFolderRefusal Evaluate(
        string folder, RawSecurityDescriptor security, bool isLink, bool isDirectory, bool checkAccess)
    {
        if (isLink)
        {
            return new DataFolderRefusal(folder, DataFolderProblem.Link);
        }

        if (!isDirectory)
        {
            return new DataFolderRefusal(folder, DataFolderProblem.File);
        }

        if (security.Owner is null)
        {
            return new DataFolderRefusal(folder, DataFolderProblem.Unreadable);
        }

        // The DACL is checked before the owner, so that a refusal names an account that may replace the folder first.
        if (checkAccess)
        {
            // A null DACL grants every right to everyone.
            if (security.DiscretionaryAcl is null)
            {
                return new DataFolderRefusal(
                    folder, DataFolderProblem.Access, new SecurityIdentifier(WellKnownSidType.WorldSid, null));
            }

            foreach (GenericAce ace in security.DiscretionaryAcl)
            {
                switch (ace.AceType)
                {
                    // A deny entry only takes access away.
                    case AceType.AccessDenied:
                    case AceType.AccessDeniedCallback:
                    case AceType.AccessDeniedObject:
                    case AceType.AccessDeniedCallbackObject:
                        continue;
                    case AceType.AccessAllowed:
                    case AceType.AccessAllowedCallback:
                        break;
                    // An entry of another type, such as an object entry, which directory service objects use, isn't
                    // expected on a folder, so the installer refuses rather than guesses what it grants.
                    default:
                        return new DataFolderRefusal(folder, DataFolderProblem.Unreadable);
                }

                // An inherit-only entry applies to the entries created below the folder, not to the folder.
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0)
                {
                    continue;
                }

                CommonAce entry = (CommonAce)ace;

                // UNTESTED: an entry for a member of Administrators, such as an administrator's user account, is trusted
                // as the owner rule trusts it; no test runs with such an account.
                // When changing this, keep trusting in an entry exactly the accounts trusted as the owner.
                if ((unchecked((uint)entry.AccessMask) & ReplaceRights) != 0
                    && entry.SecurityIdentifier != OwnerRights
                    && !IsAppContainer(entry.SecurityIdentifier)
                    && !IsTrusted(entry.SecurityIdentifier))
                {
                    return new DataFolderRefusal(folder, DataFolderProblem.Access, entry.SecurityIdentifier);
                }
            }
        }

        return IsTrusted(security.Owner) ? null : new DataFolderRefusal(folder, DataFolderProblem.Owner, security.Owner);
    }

    /// <summary>
    /// Whether <paramref name="sid"/> may own the Gateway's data, as <see cref="SecureDirectory.IsTrustedOwner"/>
    /// decides.
    /// </summary>
    private static bool IsTrusted(SecurityIdentifier sid)
    {
        try
        {
            return SecureDirectory.IsTrustedOwner(sid);
        }
        catch (Exception)
        {
            // An account whose group membership can't be resolved isn't known to be an administrator.
            return false;
        }
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names with <paramref name="open"/>, which opens a link itself rather than
    /// its target, and evaluates its security.
    /// </summary>
    /// <param name="handle">The open entry, or <c>null</c> when nothing exists at <paramref name="path"/>.</param>
    /// <returns>The refusal, or <c>null</c> when the entry passes or doesn't exist.</returns>
    private static DataFolderRefusal Inspect(
        string path, Func<string, SafeFileHandle> open, bool checkAccess, ILogger logger, out SafeFileHandle handle)
    {
        handle = null;

        try
        {
            handle = open(path);
            (RawSecurityDescriptor security, bool isLink, bool isDirectory) = SecureDirectory.ReadSecurity(handle);
            DataFolderRefusal refusal = Evaluate(path, security, isLink, isDirectory, checkAccess);

            logger.Log(refusal is null
                ? $"checked {path}"
                : $"refused {path}: {refusal.Problem} {refusal.Account}");

            return refusal;
        }
        catch (Win32Exception e) when (handle is null && SecureDirectory.IsNotFound(e))
        {
            return null;
        }
        catch (Exception e)
        {
            logger.Log($"failed to read the owner and the DACL of {path}: {e}");
            return new DataFolderRefusal(path, DataFolderProblem.Unreadable);
        }
    }

    /// <summary>
    /// Whether <paramref name="sid"/> is an AppContainer package SID (<c>S-1-15-2-…</c>) or capability SID
    /// (<c>S-1-15-3-…</c>).
    /// </summary>
    /// <remarks>
    /// An entry for one never grants access by itself: Windows grants an AppContainer process only the access that both
    /// its user and its package and capabilities are granted, and no other process holds these SIDs.
    /// </remarks>
    private static bool IsAppContainer(SecurityIdentifier sid)
    {
        // SECURITY_APP_PACKAGE_AUTHORITY, then SECURITY_APP_PACKAGE_BASE_RID or SECURITY_CAPABILITY_BASE_RID.
        string[] parts = sid.Value.Split('-');
        return parts.Length > 3 && parts[2] == "15" && parts[3] is "2" or "3";
    }
}
