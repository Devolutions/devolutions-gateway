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
/// A folder of the agent's data path that the installer refuses to use.
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
            DataFolderProblem.Owner => Strings.DataFolderOwnedByUntrustedAccount,
            DataFolderProblem.Access => Strings.DataFolderReplaceableByUntrustedAccount,
            DataFolderProblem.Unreadable => Strings.DataFolderSecurityUnreadable,
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
    /// Checks <c>Devolutions</c> and <c>Devolutions\Agent</c> under <paramref name="root"/> without changing anything.
    /// </summary>
    /// <returns>The first refusal, or <c>null</c> when both folders pass.</returns>
    internal static DataFolderRefusal Check(string root, ILogger logger)
    {
        string devolutions = Path.Combine(root, Devolutions);
        DataFolderRefusal refusal = Inspect(devolutions, hold: true, checkAccess: true, logger, out SafeFileHandle handle);

        using (handle)
        {
            if (refusal is not null || handle is null)
            {
                return refusal;
            }

            // UNTESTED: an existing Agent is refused when it is a link or has an untrusted owner, here and in Create.
            // A test reaches it only below a Devolutions folder that passes, which needs an owner that a test without
            // elevation can't set.
            // When changing this, keep Agent checked in both, without the DACL rule, as the installer resets its DACL.
            refusal = Inspect(Path.Combine(devolutions, Agent), hold: false, checkAccess: false, logger, out SafeFileHandle agent);
            agent?.Dispose();

            return refusal;
        }
    }

    /// <summary>
    /// Creates <c>Devolutions\Agent</c> under <paramref name="root"/> with the security descriptor
    /// <paramref name="sddl"/>, after checking <c>Devolutions</c> and, when it already exists, <c>Agent</c>.
    /// </summary>
    /// <remarks>
    /// A missing <c>Devolutions</c> is created with the DACL it inherits, then checked like an existing one.
    /// <c>Agent</c> gets its security descriptor when it is created, so that it never exists with the DACL it would
    /// inherit from ProgramData, which lets users add entries.
    /// </remarks>
    /// <returns>The first refusal, in which case nothing is created below <c>Devolutions</c>, or <c>null</c>.</returns>
    /// <exception cref="IOException"><c>Agent</c> exists and is not a directory.</exception>
    internal static DataFolderRefusal Create(string root, string sddl, ILogger logger)
    {
        string devolutions = Path.Combine(root, Devolutions);
        string agent = Path.Combine(devolutions, Agent);

        Directory.CreateDirectory(devolutions);

        // UNTESTED: the handle on Devolutions denies delete sharing until Agent is created or checked below it.
        // Renaming or replacing a folder needs delete access to it, so Agent is created or checked in the folder just
        // checked, not in one put at that path afterwards.
        // When changing this, keep the share mode of that handle and keep it open until Agent is done.
        DataFolderRefusal refusal = Inspect(devolutions, hold: true, checkAccess: true, logger, out SafeFileHandle handle);

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

            refusal = Inspect(agent, hold: false, checkAccess: false, logger, out SafeFileHandle existing);
            existing?.Dispose();

            if (refusal is null && !Directory.Exists(agent))
            {
                throw new IOException($"{agent} exists and is not a directory");
            }

            return refusal;
        }
    }

    /// <summary>
    /// Whether the installer refuses to use <paramref name="folder"/>, given its security descriptor and whether it is a
    /// link.
    /// </summary>
    /// <param name="checkAccess">
    /// Whether to refuse a DACL that lets an account other than SYSTEM, Administrators or TrustedInstaller replace the
    /// folder or what it contains.
    /// </param>
    /// <returns>The refusal, or <c>null</c> when the folder passes.</returns>
    internal static DataFolderRefusal Evaluate(
        string folder, RawSecurityDescriptor security, bool isLink, bool checkAccess)
    {
        if (isLink)
        {
            return new DataFolderRefusal(folder, DataFolderProblem.Link);
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
                // An inherit-only entry applies to the entries created below the folder, not to the folder.
                if (ace is KnownAce entry
                    && IsAllow(entry.AceType)
                    && (entry.AceFlags & AceFlags.InheritOnly) == 0
                    && (unchecked((uint)entry.AccessMask) & ReplaceRights) != 0
                    && !SecureDirectory.IsPrivileged(entry.SecurityIdentifier))
                {
                    return new DataFolderRefusal(folder, DataFolderProblem.Access, entry.SecurityIdentifier);
                }
            }
        }

        bool trusted;

        try
        {
            trusted = SecureDirectory.IsTrustedOwner(security.Owner);
        }
        catch (Exception)
        {
            // An owner whose group membership can't be resolved isn't known to be an administrator.
            trusted = false;
        }

        return trusted ? null : new DataFolderRefusal(folder, DataFolderProblem.Owner, security.Owner);
    }

    /// <summary>
    /// Opens the entry <paramref name="path"/> names, a link itself rather than its target, and evaluates its security.
    /// </summary>
    /// <param name="handle">The open entry, or <c>null</c> when nothing exists at <paramref name="path"/>.</param>
    /// <returns>The refusal, or <c>null</c> when the entry passes or doesn't exist.</returns>
    private static DataFolderRefusal Inspect(
        string path, bool hold, bool checkAccess, ILogger logger, out SafeFileHandle handle)
    {
        handle = null;

        try
        {
            handle = SecureDirectory.OpenToRead(path, hold);
            (RawSecurityDescriptor security, bool isLink) = SecureDirectory.ReadSecurity(handle);
            DataFolderRefusal refusal = Evaluate(path, security, isLink, checkAccess);

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

    private static bool IsAllow(AceType type) =>
        type is AceType.AccessAllowed
            or AceType.AccessAllowedCompound
            or AceType.AccessAllowedObject
            or AceType.AccessAllowedCallback
            or AceType.AccessAllowedCallbackObject;
}
