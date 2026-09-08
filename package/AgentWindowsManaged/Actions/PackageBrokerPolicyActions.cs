using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

[assembly: InternalsVisibleTo("DevolutionsAgent.Installer.Tests")]

namespace DevolutionsAgent.Actions;

public static class PackageBrokerPolicyActions
{
    private static string ProgramDataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Devolutions",
        "Agent");

    internal static string ProgramDataPackageBrokerDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Devolutions",
        "PackageBroker");

    private static string DestinationPolicyPath =>
        Path.Combine(ProgramDataPackageBrokerDirectory, "package-broker-policy.json");

    private static string LegacyPolicyPath =>
        Path.Combine(ProgramDataDirectory, "package-broker-policy.json");

    private static uint PackageBrokerSecurityInformation =>
        WinAPI.OWNER_SECURITY_INFORMATION |
        WinAPI.GROUP_SECURITY_INFORMATION |
        WinAPI.DACL_SECURITY_INFORMATION |
        WinAPI.PROTECTED_DACL_SECURITY_INFORMATION;

    [CustomAction]
    public static ActionResult EnsureProgramDataPackageBrokerDirectory(Session session)
    {
        try
        {
            EnsureSecureDirectoryTree(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                ProgramDataPackageBrokerDirectory);
            session.Log($"securely created or verified {ProgramDataPackageBrokerDirectory}");
            return ActionResult.Success;
        }
        catch (Exception error)
        {
            session.Log($"failed to securely create or verify {ProgramDataPackageBrokerDirectory}: {error}");
            return ActionResult.Failure;
        }
    }

    [CustomAction]
    public static ActionResult MigrateLegacyPackageBrokerPolicy(Session session)
    {
        string destination = DestinationPolicyPath;
        string sourcePath = LegacyPolicyPath;
        string temporary = Path.Combine(
            ProgramDataPackageBrokerDirectory,
            $".package-broker-policy.migration-{Guid.NewGuid():N}.tmp");
        string marker = MigrationMarkerPath(session);
        bool migrationStarted = false;
        MigrationRecord? migrationRecord = null;

        try
        {
            LogLegacyYamlMigrationRequired(session, destination);
            using PinnedPath destinationPath = PinPathWithoutReparse(
                destination,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
            if (destinationPath.Leaf != null)
            {
                VerifyPackageBrokerSecurity(SecurityFromHandle(destinationPath.Leaf, isDirectory: false));
                session.Log($"package broker policy already exists at {destination}; legacy migration skipped");
                return ActionResult.Success;
            }

            using PinnedPath source = PinPathWithoutReparse(
                sourcePath,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.READ_CONTROL);
            if (source.Leaf == null)
            {
                return ActionResult.Success;
            }

            if (!TryVerifyLegacyPolicySourceSecurity(
                SecurityFromHandle(source.Leaf, isDirectory: false),
                out string sourceSecurityDiagnostic))
            {
                session.Log(
                    $"skipping automatic package broker policy migration from {sourcePath}: " +
                    $"{sourceSecurityDiagnostic}. The source was left untouched and no destination was created. " +
                    "Restrict the source owner and write access to SYSTEM/Administrators, then validate and migrate it manually.");
                return ActionResult.Success;
            }

            string sourceIdentity = FileIdentity(source.Leaf);
            string sourceDigest = FileContentDigest(source.Leaf);
            migrationStarted = true;
            using (FileStream sourceStream = OpenPinnedFileStream(source.Leaf))
            using (FileStream target = new(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                sourceStream.CopyTo(target);
                target.Flush(true);
            }

            SetFileSecurity(temporary, Includes.PROGRAM_DATA_PACKAGE_BROKER_FILE_SDDL);
            using (PinnedPath temporaryPath = PinPathWithoutReparse(
                temporary,
                leafIsDirectory: false,
                allowMissingLeaf: false,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL))
            {
                VerifyPackageBrokerSecurity(SecurityFromHandle(temporaryPath.Leaf, isDirectory: false));
                migrationRecord = new MigrationRecord(
                    sourceIdentity,
                    sourceDigest,
                    FileIdentity(temporaryPath.Leaf),
                    FileContentDigest(temporaryPath.Leaf));
            }

            MigrationRecord record = migrationRecord.Value;
            using PinnedPath markerPath = WriteMigrationMarker(marker, record);
            if (MoveFileNoReplace(temporary, destination) == NoReplaceMoveResult.DestinationExists)
            {
                VerifyPackageBrokerSecurity(SecurityFromHandle(markerPath.Leaf, isDirectory: false));
                DeleteFileByHandle(markerPath.Leaf);
                session.Log(
                    $"package broker policy appeared at {destination} during migration; " +
                    "the external destination and legacy source were preserved");
                return ActionResult.Success;
            }

            using PinnedPath migratedPath = PinPathWithoutReparse(
                destination,
                leafIsDirectory: false,
                allowMissingLeaf: false,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
            VerifyPackageBrokerSecurity(SecurityFromHandle(migratedPath.Leaf, isDirectory: false));
            if (!FileIdentityAndDigestMatch(
                migratedPath.Leaf,
                record.DestinationIdentity,
                record.DestinationDigest))
            {
                throw new InvalidOperationException("migrated package broker policy identity changed unexpectedly");
            }

            session.Log($"migrated legacy package broker policy from {sourcePath} to {destination}");
            return ActionResult.Success;
        }
        catch (Exception error)
        {
            if (!migrationStarted)
            {
                session.Log(
                    $"skipping automatic package broker policy migration because its paths could not be trusted: {error}");
                return ActionResult.Success;
            }
            session.Log($"failed to migrate legacy package broker policy: {error}");
            return ActionResult.Failure;
        }
        finally
        {
            TryDeleteTemporaryFile(
                session,
                temporary,
                migrationRecord?.DestinationIdentity,
                migrationRecord?.DestinationDigest);
        }
    }

    [CustomAction]
    public static ActionResult RollbackLegacyPackageBrokerPolicyMigration(Session session)
    {
        string marker = MigrationMarkerPath(session);
        string destination = DestinationPolicyPath;

        try
        {
            using PinnedPath markerPath = PinPathWithoutReparse(
                marker,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
            if (markerPath.Leaf == null)
            {
                return ActionResult.Success;
            }

            VerifyPackageBrokerSecurity(SecurityFromHandle(markerPath.Leaf, isDirectory: false));
            MigrationRecord record = ReadMigrationMarker(markerPath.Leaf);

            using PinnedPath destinationPath = PinPathWithoutReparse(
                destination,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
            if (destinationPath.Leaf != null &&
                FileIdentityAndDigestMatch(
                    destinationPath.Leaf,
                    record.DestinationIdentity,
                    record.DestinationDigest))
            {
                VerifyPackageBrokerSecurity(SecurityFromHandle(destinationPath.Leaf, isDirectory: false));
                DeleteFileByHandle(destinationPath.Leaf);
            }

            VerifyPackageBrokerSecurity(SecurityFromHandle(markerPath.Leaf, isDirectory: false));
            DeleteFileByHandle(markerPath.Leaf);
        }
        catch (Exception error)
        {
            session.Log($"failed to roll back legacy package broker policy migration: {error}");
        }

        return ActionResult.Success;
    }

    [CustomAction]
    public static ActionResult CommitLegacyPackageBrokerPolicyMigration(Session session) =>
        RunBestEffortCommit(
            session.Log,
            () => CommitLegacyPackageBrokerPolicyMigrationCore(session));

    internal static ActionResult RunBestEffortCommit(Action<string> log, Action commit)
    {
        try
        {
            commit();
        }
        catch (Exception error)
        {
            log($"failed to commit legacy package broker policy migration: {error}");
        }

        return ActionResult.Success;
    }

    private static void CommitLegacyPackageBrokerPolicyMigrationCore(Session session)
    {
        string marker = MigrationMarkerPath(session);
        string sourcePath = LegacyPolicyPath;
        using PinnedPath markerPath = PinPathWithoutReparse(
            marker,
            leafIsDirectory: false,
            allowMissingLeaf: true,
            leafAccess: WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
        if (markerPath.Leaf == null)
        {
            return;
        }

        VerifyPackageBrokerSecurity(SecurityFromHandle(markerPath.Leaf, isDirectory: false));
        MigrationRecord record = ReadMigrationMarker(markerPath.Leaf);

        bool sourceChanged;
        bool removeSource;
        using (PinnedPath source = PinPathWithoutReparse(
            sourcePath,
            leafIsDirectory: false,
            allowMissingLeaf: true,
            leafAccess: WinAPI.GENERIC_READ | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL))
        {
            sourceChanged =
                source.Leaf == null ||
                !FileIdentityAndDigestMatch(source.Leaf, record.SourceIdentity, record.SourceDigest);
            removeSource = !sourceChanged;
            if (removeSource &&
                IsLegacyPackageBrokerPolicyExplicitlyConfigured(
                    sourcePath,
                    source.Leaf,
                    out string configuredDiagnostic))
            {
                session.Log(
                    $"preserving the configured legacy package broker policy during commit: {configuredDiagnostic}");
                removeSource = false;
            }
            if (removeSource &&
                !TryVerifyLegacyPolicySourceSecurity(
                    SecurityFromHandle(source.Leaf, isDirectory: false),
                    out string sourceSecurityDiagnostic))
            {
                session.Log(
                    $"preserving the legacy package broker policy during commit: {sourceSecurityDiagnostic}");
                removeSource = false;
            }
        }

        VerifyPackageBrokerSecurity(SecurityFromHandle(markerPath.Leaf, isDirectory: false));
        DeleteFileByHandle(markerPath.Leaf);

        if (!removeSource)
        {
            if (sourceChanged)
            {
                session.Log(
                    "legacy package broker policy changed after migration; preserving the current source");
            }
            return;
        }

        TryDeleteLegacyPolicySource(session, sourcePath, record);
    }

    internal static void EnsureSecureDirectoryTree(string programData, string target)
    {
        string programDataPath = Path.GetFullPath(programData);
        string targetPath = Path.GetFullPath(target);
        string prefix = programDataPath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!targetPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{targetPath} is outside the ProgramData directory");
        }

        string[] components = targetPath
            .Substring(prefix.Length)
            .Split(new[] { Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
        if (components.Length != 2 ||
            !string.Equals(components[0], "Devolutions", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(components[1], "PackageBroker", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("package broker directory has an unexpected shape");
        }

        List<SafeFileHandle> handles = new();
        try
        {
            SafeFileHandle programDataHandle = OpenPathWithoutReparse(
                programDataPath,
                isDirectory: true,
                WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL,
                WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE,
                allowMissing: false);
            handles.Add(programDataHandle);
            VerifyResolvedPath(programDataHandle, programDataPath);
            VerifyTrustedDirectorySecurity(SecurityFromHandle(programDataHandle, isDirectory: true));

            string vendorPath = Path.Combine(programDataPath, components[0]);
            SafeFileHandle vendorHandle = OpenPathWithoutReparse(
                vendorPath,
                isDirectory: true,
                WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL,
                WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE,
                allowMissing: true);
            if (vendorHandle == null)
            {
                Directory.CreateDirectory(vendorPath);
                vendorHandle = OpenPathWithoutReparse(
                    vendorPath,
                    isDirectory: true,
                    WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL,
                    WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE,
                    allowMissing: false);
            }
            handles.Add(vendorHandle);
            VerifyResolvedPath(vendorHandle, vendorPath);
            VerifyTrustedDirectorySecurity(SecurityFromHandle(vendorHandle, isDirectory: true));

            string leafPath = Path.Combine(vendorPath, components[1]);
            SafeFileHandle leafHandle = OpenPathWithoutReparse(
                leafPath,
                isDirectory: true,
                WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL,
                WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE,
                allowMissing: true);
            bool leafCreated = leafHandle == null;
            if (leafCreated)
            {
                CreateDirectoryWithSecurity(leafPath, Includes.PROGRAM_DATA_PACKAGE_BROKER_SDDL);
                leafHandle = OpenPathWithoutReparse(
                    leafPath,
                    isDirectory: true,
                    WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL,
                    WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE,
                    allowMissing: false);
            }
            handles.Add(leafHandle);
            VerifyResolvedPath(leafHandle, leafPath);
            FileSystemSecurity leafSecurity = SecurityFromHandle(leafHandle, isDirectory: true);
            VerifyPackageBrokerSecurity(leafSecurity);
            if (leafCreated)
            {
                VerifySecurityDescriptor(leafSecurity, Includes.PROGRAM_DATA_PACKAGE_BROKER_SDDL);
            }
        }
        finally
        {
            foreach (SafeFileHandle handle in handles)
            {
                handle.Dispose();
            }
        }
    }

    internal static void VerifyPackageBrokerSecurity(FileSystemSecurity security)
    {
        VerifyDaclPresentAndNonEmpty(security, "package broker path");
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        if (!owner.Equals(system) && !owner.Equals(administrators))
        {
            throw new InvalidOperationException($"package broker path has untrusted owner {owner.Value}");
        }
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidOperationException("package broker path DACL inheritance is not protected");
        }

        FileSystemAccessRule[] rules = security
            .GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        bool IsExpectedFullControl(FileSystemAccessRule rule, SecurityIdentifier sid) =>
            rule.IdentityReference.Equals(sid) &&
            rule.AccessControlType == AccessControlType.Allow &&
            (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl;
        if (rules.Length != 2 ||
            !rules.Any(rule => IsExpectedFullControl(rule, system)) ||
            !rules.Any(rule => IsExpectedFullControl(rule, administrators)))
        {
            throw new InvalidOperationException("package broker path DACL is not SYSTEM/Administrators-only");
        }
    }

    internal static bool TryVerifyLegacyPolicySourceSecurity(
        FileSystemSecurity security,
        out string diagnostic)
    {
        try
        {
            VerifyLegacyPolicySourceSecurity(security);
            diagnostic = null;
            return true;
        }
        catch (InvalidOperationException error)
        {
            diagnostic = error.Message;
            return false;
        }
    }

    internal static bool TryReadConfiguredPolicyPath(
        string configJson,
        out string configuredPath,
        out string diagnostic)
    {
        configuredPath = null;
        diagnostic = null;
        try
        {
            if (ContainsNonStrictJsonSyntax(configJson))
            {
                diagnostic = "configuration uses non-strict JSON syntax";
                return false;
            }

            using (JsonTextReader syntaxReader = new(new StringReader(configJson)))
            {
                while (syntaxReader.Read())
                {
                    if (syntaxReader.TokenType == JsonToken.Comment ||
                        syntaxReader.TokenType == JsonToken.Undefined ||
                        ((syntaxReader.TokenType == JsonToken.String ||
                          syntaxReader.TokenType == JsonToken.PropertyName) &&
                         syntaxReader.QuoteChar != '"'))
                    {
                        diagnostic = "configuration uses non-strict JSON syntax";
                        return false;
                    }
                }
            }

            using JsonTextReader reader = new(new StringReader(configJson))
            {
                DateParseHandling = DateParseHandling.None,
                SupportMultipleContent = false,
            };
            JObject config = JObject.Load(
                reader,
                new JsonLoadSettings
                {
                    CommentHandling = CommentHandling.Load,
                    DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error,
                });
            if (reader.Read())
            {
                diagnostic = "configuration contains multiple JSON values";
                return false;
            }

            JToken token = config["PackageBroker"]?["PolicyPath"];
            if (token == null || token.Type == JTokenType.Null)
            {
                return true;
            }
            if (token.Type != JTokenType.String || string.IsNullOrWhiteSpace(token.Value<string>()))
            {
                diagnostic = "PackageBroker.PolicyPath is not a valid path string";
                return false;
            }

            configuredPath = token.Value<string>();
            if (!Path.IsPathRooted(configuredPath))
            {
                diagnostic = "PackageBroker.PolicyPath is not absolute";
                return false;
            }
            return true;
        }
        catch (Exception error) when (
            error is JsonException ||
            error is ArgumentException)
        {
            diagnostic = $"configuration could not be parsed safely: {error.Message}";
            return false;
        }
    }

    internal static bool ContainsNonStrictJsonSyntax(string json)
    {
        bool inString = false;
        bool escaped = false;
        for (int index = 0; index < json.Length; index++)
        {
            char current = json[index];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (current == '\\')
                {
                    escaped = true;
                }
                else if (current == '"')
                {
                    inString = false;
                }
                continue;
            }

            if (current == '"')
            {
                inString = true;
                continue;
            }
            if (current == '/' &&
                index + 1 < json.Length &&
                (json[index + 1] == '/' || json[index + 1] == '*'))
            {
                return true;
            }
            if (current != ',')
            {
                continue;
            }

            int next = index + 1;
            while (next < json.Length && char.IsWhiteSpace(json[next]))
            {
                next++;
            }
            if (next < json.Length && (json[next] == '}' || json[next] == ']'))
            {
                return true;
            }
        }
        return inString || escaped;
    }

    internal static PinnedPath PinPathWithoutReparse(
        string path,
        bool leafIsDirectory,
        bool allowMissingLeaf,
        uint leafAccess)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath);
        string parent = Path.GetDirectoryName(fullPath);
        Stack<string> ancestors = new();
        while (!string.IsNullOrEmpty(parent))
        {
            ancestors.Push(parent);
            if (string.Equals(parent, root, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
            parent = Path.GetDirectoryName(parent);
        }

        List<SafeFileHandle> handles = new();
        try
        {
            foreach (string ancestor in ancestors)
            {
                SafeFileHandle ancestorHandle = OpenPathWithoutReparse(
                    ancestor,
                    isDirectory: true,
                    WinAPI.FILE_READ_ATTRIBUTES,
                    WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE,
                    allowMissing: false);
                VerifyResolvedPath(ancestorHandle, ancestor);
                handles.Add(ancestorHandle);
            }

            uint shareMode = (leafAccess & WinAPI.GENERIC_READ) != 0
                ? WinAPI.FILE_SHARE_READ
                : WinAPI.FILE_SHARE_READ | WinAPI.FILE_SHARE_WRITE;
            SafeFileHandle leaf = OpenPathWithoutReparse(
                fullPath,
                leafIsDirectory,
                leafAccess,
                shareMode,
                allowMissingLeaf);
            if (leaf != null)
            {
                VerifyResolvedPath(leaf, fullPath);
                handles.Add(leaf);
            }
            return new PinnedPath(handles, leaf);
        }
        catch
        {
            foreach (SafeFileHandle handle in handles)
            {
                handle.Dispose();
            }
            throw;
        }
    }

    internal static string FileIdentity(SafeFileHandle handle)
    {
        if (!WinAPI.GetFileInformationByHandle(handle, out WinAPI.ByHandleFileInformation information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "failed to query file identity");
        }
        return string.Join(
            ":",
            information.VolumeSerialNumber,
            information.FileIndexHigh,
            information.FileIndexLow);
    }

    internal static string FileContentDigest(SafeFileHandle handle)
    {
        using FileStream stream = OpenPinnedFileStream(handle);
        using SHA256 sha256 = SHA256.Create();
        return Convert.ToBase64String(sha256.ComputeHash(stream));
    }

    internal static bool FileIdentityAndDigestMatch(
        SafeFileHandle handle,
        string expectedIdentity,
        string expectedDigest) =>
        string.Equals(FileIdentity(handle), expectedIdentity, StringComparison.Ordinal) &&
        string.Equals(FileContentDigest(handle), expectedDigest, StringComparison.Ordinal);

    internal static void DeleteFileByHandle(SafeFileHandle handle)
    {
        WinAPI.FileDispositionInfo disposition = new() { DeleteFile = true };
        if (!WinAPI.SetFileInformationByHandle(
            handle,
            WinAPI.FileInfoByHandleClass.FileDispositionInfo,
            ref disposition,
            (uint)Marshal.SizeOf<WinAPI.FileDispositionInfo>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "failed to delete the pinned file");
        }
    }

    internal static bool DeleteFileIfIdentityAndDigestMatch(
        SafeFileHandle handle,
        string expectedIdentity,
        string expectedDigest)
    {
        if (!FileIdentityAndDigestMatch(handle, expectedIdentity, expectedDigest))
        {
            return false;
        }

        DeleteFileByHandle(handle);
        return true;
    }

    internal static MigrationRecord ReadMigrationMarkerJson(string markerJson)
    {
        JObject document = JObject.Parse(markerJson);
        string sourceIdentity = document.Value<string>("SourceIdentity");
        string sourceDigest = document.Value<string>("SourceDigest");
        string destinationIdentity = document.Value<string>("DestinationIdentity");
        string destinationDigest = document.Value<string>("DestinationDigest");
        if (string.IsNullOrEmpty(sourceIdentity) ||
            string.IsNullOrEmpty(sourceDigest) ||
            string.IsNullOrEmpty(destinationIdentity) ||
            string.IsNullOrEmpty(destinationDigest))
        {
            throw new InvalidOperationException("package broker migration marker is incomplete");
        }
        return new MigrationRecord(sourceIdentity, sourceDigest, destinationIdentity, destinationDigest);
    }

    private static string MigrationMarkerPath(Session session) =>
        Path.Combine(
            ProgramDataPackageBrokerDirectory,
            $".legacy-policy-migration-{session.Get(AgentProperties.installId)}.marker");

    internal static NoReplaceMoveResult MoveFileNoReplace(string source, string destination)
    {
        if (WinAPI.MoveFileEx(source, destination, 0))
        {
            return NoReplaceMoveResult.Moved;
        }

        int error = Marshal.GetLastWin32Error();
        if (error == WinAPI.ERROR_FILE_EXISTS || error == WinAPI.ERROR_ALREADY_EXISTS)
        {
            return NoReplaceMoveResult.DestinationExists;
        }

        throw new Win32Exception(error, $"failed to move {source} to {destination} without replacement");
    }

    private static PinnedPath WriteMigrationMarker(string marker, MigrationRecord record)
    {
        using (FileStream markerFile = new(marker, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            byte[] markerContent = Encoding.UTF8.GetBytes(record.ToJson());
            markerFile.Write(markerContent, 0, markerContent.Length);
            markerFile.Flush(true);
        }

        SetFileSecurity(marker, Includes.PROGRAM_DATA_PACKAGE_BROKER_FILE_SDDL);
        PinnedPath markerPath = PinPathWithoutReparse(
            marker,
            leafIsDirectory: false,
            allowMissingLeaf: false,
            leafAccess: WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
        try
        {
            VerifyPackageBrokerSecurity(SecurityFromHandle(markerPath.Leaf, isDirectory: false));
            _ = ReadMigrationMarker(markerPath.Leaf);
            return markerPath;
        }
        catch
        {
            markerPath.Dispose();
            throw;
        }
    }

    private static MigrationRecord ReadMigrationMarker(SafeFileHandle marker)
    {
        using FileStream stream = OpenPinnedFileStream(marker);
        using StreamReader reader = new(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: true);
        return ReadMigrationMarkerJson(reader.ReadToEnd());
    }

    private static bool IsLegacyPackageBrokerPolicyExplicitlyConfigured(
        string sourcePath,
        SafeFileHandle source,
        out string diagnostic)
    {
        string configPath = Path.Combine(ProgramDataDirectory, "agent.json");
        try
        {
            using PinnedPath config = PinPathWithoutReparse(
                configPath,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.FILE_READ_ATTRIBUTES);
            if (config.Leaf == null)
            {
                diagnostic = null;
                return false;
            }

            string configJson;
            using (FileStream stream = OpenPinnedFileStream(config.Leaf))
            using (StreamReader reader = new(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
                detectEncodingFromByteOrderMarks: false))
            {
                configJson = reader.ReadToEnd();
            }
            if (!TryReadConfiguredPolicyPath(configJson, out string configuredPath, out diagnostic))
            {
                return true;
            }
            if (configuredPath == null)
            {
                return false;
            }

            using PinnedPath configured = PinPathWithoutReparse(
                configuredPath,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.FILE_READ_ATTRIBUTES);
            if (configured.Leaf == null)
            {
                diagnostic = $"PackageBroker.PolicyPath in {configPath} could not be resolved safely";
                return true;
            }
            if (!string.Equals(FileIdentity(configured.Leaf), FileIdentity(source), StringComparison.Ordinal))
            {
                diagnostic = null;
                return false;
            }

            diagnostic = $"PackageBroker.PolicyPath in {configPath} still points to {sourcePath}";
            return true;
        }
        catch (Exception error)
        {
            diagnostic = $"could not safely determine PackageBroker.PolicyPath from {configPath}: {error.Message}";
            return true;
        }
    }

    private static void VerifyLegacyPolicySourceSecurity(FileSystemSecurity security)
    {
        const FileSystemRights unsafeRights =
            FileSystemRights.WriteData |
            FileSystemRights.AppendData |
            FileSystemRights.WriteAttributes |
            FileSystemRights.WriteExtendedAttributes |
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership |
            (FileSystemRights)0x40000000 |
            (FileSystemRights)0x10000000;
        VerifyTrustedOwnerAndNoUnsafeGrants(
            security,
            unsafeRights,
            "legacy policy",
            "unsafe write or tamper");
    }

    internal static void VerifyTrustedDirectorySecurity(FileSystemSecurity security)
    {
        const FileSystemRights tamperRights =
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership |
            (FileSystemRights)0x10000000;
        VerifyTrustedOwnerAndNoUnsafeGrants(
            security,
            tamperRights,
            "directory",
            "path-tampering");
    }

    private static void VerifyTrustedOwnerAndNoUnsafeGrants(
        FileSystemSecurity security,
        FileSystemRights unsafeRights,
        string subject,
        string accessDescription)
    {
        VerifyDaclPresentAndNonEmpty(security, subject);
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier trustedInstaller =
            (SecurityIdentifier)new NTAccount(@"NT SERVICE\TrustedInstaller").Translate(typeof(SecurityIdentifier));
        SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        if (!owner.Equals(system) && !owner.Equals(administrators) && !owner.Equals(trustedInstaller))
        {
            throw new InvalidOperationException($"{subject} has untrusted owner {owner.Value}");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                (rule.FileSystemRights & unsafeRights) == 0)
            {
                continue;
            }

            SecurityIdentifier identity = (SecurityIdentifier)rule.IdentityReference;
            if (!identity.Equals(system) &&
                !identity.Equals(administrators) &&
                !identity.Equals(trustedInstaller))
            {
                throw new InvalidOperationException(
                    $"{subject} grants {accessDescription} rights to {identity.Value}");
            }
        }
    }

    private static void VerifyDaclPresentAndNonEmpty(FileSystemSecurity security, string subject)
    {
        RawSecurityDescriptor descriptor =
            new(security.GetSecurityDescriptorBinaryForm(), 0);
        if (!descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) ||
            descriptor.DiscretionaryAcl == null)
        {
            throw new InvalidOperationException($"{subject} has a NULL DACL granting full control to everyone");
        }
        if (descriptor.DiscretionaryAcl.Count == 0)
        {
            throw new InvalidOperationException($"{subject} has an empty DACL with no trusted access entries");
        }
    }

    internal static void CreateDirectoryWithSecurity(string path, string sddl)
    {
        const uint sdRevision = 1;
        if (!WinAPI.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            sdRevision,
            out IntPtr securityDescriptor,
            out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"failed to create security descriptor for {path}");
        }

        try
        {
            WinAPI.SECURITY_ATTRIBUTES attributes = new()
            {
                nLength = (uint)Marshal.SizeOf<WinAPI.SECURITY_ATTRIBUTES>(),
                lpSecurityDescriptor = securityDescriptor,
                bInheritHandle = false,
            };
            if (!WinAPI.CreateDirectory(path, ref attributes))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != WinAPI.ERROR_ALREADY_EXISTS)
                {
                    throw new Win32Exception(error, $"failed to securely create {path}");
                }
            }
        }
        finally
        {
            WinAPI.LocalFree(securityDescriptor);
        }
    }

    private static void SetFileSecurity(string path, string sddl)
    {
        const uint sdRevision = 1;
        if (!WinAPI.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            sdRevision,
            out IntPtr securityDescriptor,
            out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"failed to create security descriptor for {path}");
        }

        try
        {
            if (!WinAPI.SetFileSecurityW(path, PackageBrokerSecurityInformation, securityDescriptor))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"failed to secure {path}");
            }
        }
        finally
        {
            WinAPI.LocalFree(securityDescriptor);
        }
    }

    internal static void VerifySecurityDescriptor(FileSystemSecurity actual, string expectedSddl)
    {
        if (!actual.AreAccessRulesProtected)
        {
            throw new InvalidOperationException("new directory DACL inheritance is not protected");
        }

        const AccessControlSections sections =
            AccessControlSections.Owner |
            AccessControlSections.Group |
            AccessControlSections.Access;
        RawSecurityDescriptor expected = new(expectedSddl);
        string expectedCanonical = expected.GetSddlForm(sections);
        string actualCanonical = actual.GetSecurityDescriptorSddlForm(sections);
        if (!string.Equals(actualCanonical, expectedCanonical, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("new directory security does not match its creation descriptor");
        }
    }

    private static SafeFileHandle OpenPathWithoutReparse(
        string path,
        bool isDirectory,
        uint desiredAccess,
        uint shareMode,
        bool allowMissing)
    {
        uint flags = WinAPI.FILE_FLAG_OPEN_REPARSE_POINT;
        if (isDirectory)
        {
            flags |= WinAPI.FILE_FLAG_BACKUP_SEMANTICS;
        }

        SafeFileHandle handle = WinAPI.CreateFile(
            path,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            WinAPI.OPEN_EXISTING,
            flags,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (allowMissing &&
                (error == WinAPI.ERROR_FILE_NOT_FOUND || error == WinAPI.ERROR_PATH_NOT_FOUND))
            {
                return null;
            }
            throw new Win32Exception(error, $"failed to open {path} without following reparse points");
        }

        if (!WinAPI.GetFileInformationByHandle(handle, out WinAPI.ByHandleFileInformation information))
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"failed to inspect {path}");
        }
        if ((information.FileAttributes & WinAPI.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            handle.Dispose();
            throw new InvalidOperationException($"{path} is a reparse point");
        }

        bool actualDirectory = (information.FileAttributes & WinAPI.FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (actualDirectory != isDirectory)
        {
            handle.Dispose();
            throw new InvalidOperationException($"{path} has an unexpected filesystem type");
        }
        if (!isDirectory && information.NumberOfLinks != 1)
        {
            handle.Dispose();
            throw new InvalidOperationException($"{path} has multiple hard links");
        }
        return handle;
    }

    private static void VerifyResolvedPath(SafeFileHandle handle, string expectedPath)
    {
        StringBuilder buffer = new(512);
        uint length = WinAPI.GetFinalPathNameByHandle(handle.DangerousGetHandle(), buffer, (uint)buffer.Capacity, 0);
        if (length == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"failed to resolve {expectedPath}");
        }
        if (length >= buffer.Capacity)
        {
            buffer.EnsureCapacity((int)length + 1);
            length = WinAPI.GetFinalPathNameByHandle(
                handle.DangerousGetHandle(),
                buffer,
                (uint)buffer.Capacity,
                0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"failed to resolve {expectedPath}");
            }
        }

        string resolved = NormalizeExtendedPath(buffer.ToString());
        string expected = Path.GetFullPath(expectedPath).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(resolved.TrimEnd(Path.DirectorySeparatorChar), expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{expectedPath} resolved to unexpected path {resolved}");
        }
    }

    private static string NormalizeExtendedPath(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string localPrefix = @"\\?\";
        if (path.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path.Substring(uncPrefix.Length);
        }
        return path.StartsWith(localPrefix, StringComparison.OrdinalIgnoreCase)
            ? path.Substring(localPrefix.Length)
            : path;
    }

    private static FileSystemSecurity SecurityFromHandle(SafeFileHandle handle, bool isDirectory)
    {
        uint information =
            WinAPI.OWNER_SECURITY_INFORMATION |
            WinAPI.GROUP_SECURITY_INFORMATION |
            WinAPI.DACL_SECURITY_INFORMATION;
        WinAPI.GetKernelObjectSecurity(handle, information, null, 0, out uint requiredSize);
        int error = Marshal.GetLastWin32Error();
        if (requiredSize == 0 || error != WinAPI.ERROR_INSUFFICIENT_BUFFER)
        {
            throw new Win32Exception(error, "failed to query pinned path security descriptor size");
        }

        byte[] descriptor = new byte[requiredSize];
        if (!WinAPI.GetKernelObjectSecurity(
            handle,
            information,
            descriptor,
            (uint)descriptor.Length,
            out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "failed to query pinned path security descriptor");
        }

        FileSystemSecurity security = isDirectory ? new DirectorySecurity() : new FileSecurity();
        security.SetSecurityDescriptorBinaryForm(descriptor);
        return security;
    }

    private static FileStream OpenPinnedFileStream(SafeFileHandle handle)
    {
        SafeFileHandle borrowedHandle = new(handle.DangerousGetHandle(), ownsHandle: false);
        FileStream stream = new(borrowedHandle, FileAccess.Read);
        stream.Position = 0;
        return stream;
    }

    private static void LogLegacyYamlMigrationRequired(Session session, string destination)
    {
        foreach (string extension in new[] { "yaml", "yml" })
        {
            string legacyYaml = Path.Combine(ProgramDataDirectory, $"package-broker-policy.{extension}");
            if (File.Exists(legacyYaml))
            {
                session.Log(
                    $"legacy YAML package broker policy remains untouched at {legacyYaml}; " +
                    $"validate and migrate it manually to strict JSON at {destination}");
            }
        }
    }

    private static void TryDeleteTemporaryFile(
        Session session,
        string path,
        string expectedIdentity,
        string expectedDigest)
    {
        try
        {
            using PinnedPath temporary = PinPathWithoutReparse(
                path,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
            if (temporary.Leaf == null)
            {
                return;
            }

            VerifyPackageBrokerSecurity(SecurityFromHandle(temporary.Leaf, isDirectory: false));
            if (expectedIdentity != null &&
                !FileIdentityAndDigestMatch(temporary.Leaf, expectedIdentity, expectedDigest))
            {
                session.Log(
                    $"package broker policy migration temporary path {path} was replaced; preserving the current file");
                return;
            }
            DeleteFileByHandle(temporary.Leaf);
        }
        catch (Exception error)
        {
            session.Log($"failed to remove package broker policy migration temporary file {path}: {error}");
        }
    }

    internal static bool TryDeleteLegacyPolicySource(
        Action<string> log,
        string sourcePath,
        MigrationRecord record)
    {
        try
        {
            using PinnedPath source = PinPathWithoutReparse(
                sourcePath,
                leafIsDirectory: false,
                allowMissingLeaf: true,
                leafAccess: WinAPI.GENERIC_READ | WinAPI.DELETE | WinAPI.FILE_READ_ATTRIBUTES | WinAPI.READ_CONTROL);
            if (source.Leaf == null)
            {
                log("legacy package broker policy disappeared before cleanup; preserving the migrated copy");
                return false;
            }
            if (!FileIdentityAndDigestMatch(source.Leaf, record.SourceIdentity, record.SourceDigest))
            {
                log("legacy package broker policy changed before cleanup; preserving both copies");
                return false;
            }
            if (!TryVerifyLegacyPolicySourceSecurity(
                SecurityFromHandle(source.Leaf, isDirectory: false),
                out string sourceSecurityDiagnostic))
            {
                log($"legacy package broker policy became unsafe before cleanup: {sourceSecurityDiagnostic}");
                return false;
            }

            return DeleteFileIfIdentityAndDigestMatch(
                source.Leaf,
                record.SourceIdentity,
                record.SourceDigest);
        }
        catch (Exception error)
        {
            log($"failed to remove the migrated legacy package broker policy; preserving both copies: {error}");
            return false;
        }
    }

    private static bool TryDeleteLegacyPolicySource(
        Session session,
        string sourcePath,
        MigrationRecord record) =>
        TryDeleteLegacyPolicySource(session.Log, sourcePath, record);

    internal sealed class PinnedPath : IDisposable
    {
        private readonly IReadOnlyList<SafeFileHandle> handles;

        internal PinnedPath(IReadOnlyList<SafeFileHandle> handles, SafeFileHandle leaf)
        {
            this.handles = handles;
            Leaf = leaf;
        }

        internal SafeFileHandle Leaf { get; }

        public void Dispose()
        {
            foreach (SafeFileHandle handle in handles)
            {
                handle.Dispose();
            }
        }
    }

    internal readonly struct MigrationRecord
    {
        internal MigrationRecord(
            string sourceIdentity,
            string sourceDigest,
            string destinationIdentity,
            string destinationDigest)
        {
            SourceIdentity = sourceIdentity;
            SourceDigest = sourceDigest;
            DestinationIdentity = destinationIdentity;
            DestinationDigest = destinationDigest;
        }

        internal string SourceIdentity { get; }
        internal string SourceDigest { get; }
        internal string DestinationIdentity { get; }
        internal string DestinationDigest { get; }

        internal string ToJson() =>
            new JObject
            {
                ["SourceIdentity"] = SourceIdentity,
                ["SourceDigest"] = SourceDigest,
                ["DestinationIdentity"] = DestinationIdentity,
                ["DestinationDigest"] = DestinationDigest,
            }.ToString(Formatting.None, Array.Empty<JsonConverter>());
    }

    internal enum NoReplaceMoveResult
    {
        Moved,
        DestinationExists,
    }
}
