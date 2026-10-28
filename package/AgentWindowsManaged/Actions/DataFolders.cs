using DevolutionsAgent.Resources;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DevolutionsAgent.Actions;

/// <summary>
/// Why the installer refuses to use a folder of the agent's data path.
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

    /// <summary>
    /// The owner of a file or a folder below <c>Agent</c>, who can always change its permissions, is not trusted.
    /// </summary>
    EntryOwner,
}

/// <summary>
/// A folder of the agent's data path that the installer refuses to use.
/// </summary>
internal sealed class DataFolderRefusal(string folder, DataFolderProblem problem, SecurityIdentifier account = null)
{
    internal string Folder { get; } = folder;

    internal DataFolderProblem Problem { get; } = problem;

    /// <summary>
    /// The owner of the folder for <see cref="DataFolderProblem.Owner"/> or of the entry for
    /// <see cref="DataFolderProblem.EntryOwner"/>, or the account the offending entry grants for
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
            DataFolderProblem.EntryOwner => Strings.DataFolderEntryOwnedByUntrustedAccount,
            _ => throw new ArgumentOutOfRangeException(nameof(this.Problem), this.Problem, null),
        };

        return string.Format(Program.Localize(productLanguage, id), this.Folder, AccountName(this.Account));
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
/// Checks <c>Devolutions</c> and <c>Devolutions\Agent</c> under ProgramData before the installer uses them.
/// </summary>
/// <remarks>
/// The installer writes the agent's data there as SYSTEM, so an account that controls either folder could redirect
/// or replace what the installer and the agent write.
/// A folder that doesn't exist yet passes.
/// Every file and folder below an existing <c>Agent</c> must have a trusted owner too, because an owner can always
/// change its entry's DACL.
/// The installer refuses an entry with an untrusted owner and never changes owners below <c>Agent</c>, so that a
/// deployment never silently takes over an entry another account created.
/// </remarks>
internal static class DataFolders
{
    private const string Devolutions = "Devolutions";

    private const string Agent = "Agent";

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
    /// Checks <c>Devolutions</c> and <c>Devolutions\Agent</c> under <paramref name="root"/>, and the owner of every
    /// file and folder below <c>Agent</c>, without changing anything and without following any link.
    /// </summary>
    /// <param name="isTrusted">
    /// Whether an account may own or replace the entry at a path; <see cref="IsTrusted(string, SecurityIdentifier)"/>
    /// when <c>null</c>.
    /// </param>
    /// <returns>The first refusal, or <c>null</c> when everything passes.</returns>
    internal static DataFolderRefusal Check(
        string root, ILogger logger, Func<string, SecurityIdentifier, bool> isTrusted = null)
    {
        // UNTESTED: the installer's actions pass no trust decision, so that owners and accounts are judged by IsTrusted,
        // here before RemoveExistingProducts and in Create.
        // Tests pass their own, because the user running them may not be a trusted owner.
        // When changing this, keep IsTrusted as the decision the actions use.
        isTrusted ??= IsTrusted;
        string devolutions = Path.Combine(root, Devolutions);
        DataFolderRefusal refusal = Inspect(
            devolutions, path => SecureDirectory.OpenToRead(path, hold: true), checkAccess: true, isTrusted, logger,
            out SafeFileHandle handle);

        using (handle)
        {
            if (refusal is not null || handle is null)
            {
                return refusal;
            }

            // UNTESTED: an existing Agent is refused when it is a link or has an untrusted owner, here and in Create.
            // Tests check the entries below Agent, not Agent itself.
            // When changing this, keep Agent checked in both, without the DACL rule, as the installer resets its DACL.
            // UNTESTED: the handle on Agent holds it until the entries below are checked, so that they are the entries
            // of the folder just checked, not of one put at that path afterwards.
            // Tests check that a held folder can't be renamed, not how long this handle stays open.
            // When changing this, keep opening Agent with hold set and keep the handle open until the walk returns.
            string agentPath = Path.Combine(devolutions, Agent);
            refusal = Inspect(
                agentPath, path => SecureDirectory.OpenToRead(path, hold: true), checkAccess: false, isTrusted, logger,
                out SafeFileHandle agent);

            using (agent)
            {
                if (refusal is not null || agent is null)
                {
                    return refusal;
                }

                return SecureDirectory.CheckOwnersBelow(agentPath, isTrusted, logger);
            }
        }
    }

    /// <summary>
    /// Creates <c>Devolutions\Agent</c> under <paramref name="root"/> with the security descriptor
    /// <paramref name="sddl"/>, after checking <c>Devolutions</c>, or checks an existing <c>Agent</c>, resets its owner
    /// and DACL to those of <paramref name="sddl"/> and removes LOCAL SERVICE from the DACLs below it, refusing an entry
    /// below it with an untrusted owner.
    /// </summary>
    /// <remarks>
    /// A missing <c>Devolutions</c> is created with the DACL it inherits, then checked like an existing one.
    /// <c>Agent</c> gets its security descriptor when it is created, so that it never exists with the DACL it would
    /// inherit from ProgramData, which lets users add entries.
    /// Until <c>Agent</c> is reset, an earlier DACL may let LOCAL SERVICE add entries below it, so the entries are checked
    /// again here, after <see cref="Check"/>.
    /// </remarks>
    /// <param name="isTrusted">
    /// Whether an account may own or replace the entry at a path; <see cref="IsTrusted(string, SecurityIdentifier)"/>
    /// when <c>null</c>.
    /// </param>
    /// <returns>
    /// The first refusal, or <c>null</c>.
    /// Nothing is created or changed below <c>Devolutions</c> before a refusal of <c>Devolutions</c> or <c>Agent</c>;
    /// before a refusal of an entry below <c>Agent</c>, <c>Agent</c> is reset and the entries walked before lose LOCAL
    /// SERVICE, as <see cref="SecureDirectory.SetSecurityAndRemoveLocalServiceBelow"/> describes.
    /// </returns>
    internal static DataFolderRefusal Create(
        string root, string sddl, ILogger logger, Func<string, SecurityIdentifier, bool> isTrusted = null)
    {
        isTrusted ??= IsTrusted;
        string devolutions = Path.Combine(root, Devolutions);
        string agent = Path.Combine(devolutions, Agent);

        SecureDirectory.Create(devolutions, sddl: null);

        // UNTESTED: the handle on Devolutions stays open until Agent is created, or checked and reset, below it, so that
        // this happens in the folder just checked, not in one put at that path afterwards.
        // Tests check that a held folder can't be renamed, not how long this handle stays open.
        // When changing this, keep the handle open until Agent is done.
        DataFolderRefusal refusal = Inspect(
            devolutions, path => SecureDirectory.OpenToRead(path, hold: true), checkAccess: true, isTrusted, logger,
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

            if (SecureDirectory.Create(agent, sddl))
            {
                logger.Log($"created {agent}");
                return null;
            }

            refusal = Inspect(
                agent, SecureDirectory.HoldToSetSecurity, checkAccess: false, isTrusted, logger,
                out SafeFileHandle existing);

            using (existing)
            {
                if (refusal is not null)
                {
                    return refusal;
                }

                if (existing is null)
                {
                    throw new IOException($"{agent} was deleted after it was found");
                }

                // UNTESTED: setting the owner to SYSTEM succeeds only for a caller allowed to give an object another
                // owner, as the installer's SYSTEM process is; tests run as a user and set the user as the owner.
                // When changing this, keep resetting the security of an existing Agent on this handle, as the agent
                // refuses a data folder whose DACL isn't the one provisioned.
                // UNTESTED: the handle on Agent holds it until the entries below are done, so that the walk below
                // happens in the folder just checked and reset, not in one put at that path afterwards.
                // Tests reach the walk through this handle, not how long it stays open.
                // When changing this, keep opening Agent with HoldToSetSecurity and keep the handle open until the walk
                // returns.
                refusal = SecureDirectory.SetSecurityAndRemoveLocalServiceBelow(existing, agent, sddl, isTrusted, logger);

                if (refusal is not null)
                {
                    return refusal;
                }

                logger.Log($"reset the owner and the DACL of {agent} and removed LOCAL SERVICE below it");

                return null;
            }
        }
    }

    /// <summary>
    /// Whether the installer refuses to use <paramref name="folder"/>, given its security descriptor and whether it is a
    /// link.
    /// </summary>
    /// <remarks>
    /// The DACL rule refuses what the agent refuses for a directory above its data, so that the installer never prepares
    /// a folder the agent then refuses to use.
    /// </remarks>
    /// <param name="checkAccess">
    /// Whether to refuse a DACL that lets an account other than SYSTEM, Administrators, TrustedInstaller, a member of
    /// Administrators or OWNER RIGHTS replace the folder or what it contains.
    /// </param>
    /// <param name="isTrusted">
    /// Whether an account may own or replace <paramref name="folder"/>;
    /// <see cref="IsTrusted(string, SecurityIdentifier)"/> when <c>null</c>.
    /// </param>
    /// <returns>The refusal, or <c>null</c> when the folder passes.</returns>
    internal static DataFolderRefusal Evaluate(
        string folder, RawSecurityDescriptor security, bool isLink, bool isDirectory, bool checkAccess,
        Func<string, SecurityIdentifier, bool> isTrusted = null)
    {
        isTrusted ??= IsTrusted;

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

        // The DACL is checked before the owner, whose trust may need a directory lookup.
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
                    // The agent refuses an entry of any other type, so the installer does too.
                    default:
                        return new DataFolderRefusal(folder, DataFolderProblem.Unreadable);
                }

                // An inherit-only entry applies to the entries created below the folder, not to the folder.
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0)
                {
                    continue;
                }

                CommonAce entry = (CommonAce)ace;

                if ((unchecked((uint)entry.AccessMask) & ReplaceRights) != 0
                    && entry.SecurityIdentifier != OwnerRights
                    && !IsAppContainer(entry.SecurityIdentifier)
                    && !isTrusted(folder, entry.SecurityIdentifier))
                {
                    return new DataFolderRefusal(folder, DataFolderProblem.Access, entry.SecurityIdentifier);
                }
            }
        }

        return isTrusted(folder, security.Owner) ? null : new DataFolderRefusal(folder, DataFolderProblem.Owner, security.Owner);
    }

    /// <summary>
    /// Whether <paramref name="sid"/> is SYSTEM, Administrators, TrustedInstaller or a member of Administrators, the
    /// accounts that may own the entry at <paramref name="path"/> or rename and replace it, whatever the entry.
    /// </summary>
    private static bool IsTrusted(string path, SecurityIdentifier sid)
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
        string path, Func<string, SafeFileHandle> open, bool checkAccess, Func<string, SecurityIdentifier, bool> isTrusted,
        ILogger logger, out SafeFileHandle handle)
    {
        handle = null;

        try
        {
            handle = open(path);
            (RawSecurityDescriptor security, bool isLink, bool isDirectory) = SecureDirectory.ReadSecurity(handle);
            DataFolderRefusal refusal = Evaluate(path, security, isLink, isDirectory, checkAccess, isTrusted);

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
