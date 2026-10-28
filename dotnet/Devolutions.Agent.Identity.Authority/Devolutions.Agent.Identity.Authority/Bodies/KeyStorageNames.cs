namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The names of the key storages where a device can hold a private key, as CONTRACT.agent-identity.md §5.7 lists them.
/// </summary>
public static class KeyStorageNames
{
    /// <summary>
    /// A key file that only the operating system's file permissions protect, which every platform can offer.
    /// </summary>
    public const string File = "file";

    /// <summary>
    /// A non-exportable machine key of the Microsoft Software Key Storage Provider, which Windows can offer.
    /// </summary>
    public const string WindowsSoftwareProvider = "windows_software_provider";

    /// <summary>
    /// A non-exportable key held by the device's TPM 2.0.
    /// </summary>
    public const string Tpm = "tpm";

    /// <summary>
    /// Every key storage name that the library knows, the only names a <see cref="KeyStoragePolicy"/> holds.
    /// </summary>
    public static IReadOnlyList<string> All { get; } = Array.AsReadOnly(new[] { File, WindowsSoftwareProvider, Tpm });

    /// <summary>
    /// Reads the key storages that an agent reports as available on its device,
    /// the value of the <see cref="AgentMetadataKeys.KeyStorageAvailable"/> metadata key.
    /// </summary>
    /// <remarks>
    /// The value joins the names with commas.
    /// Every non-empty name is kept, in reported order, whether or not <see cref="All"/> holds it,
    /// since an agent newer than the library may report a name that the contract added later.
    /// The agent reports the names without proof, so they may guide the choice of a key storage policy,
    /// but never grant or refuse anything.
    /// </remarks>
    /// <param name="value">The value of the metadata key.</param>
    /// <returns>The reported names.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    public static IReadOnlyList<string> ParseAvailable(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return Array.AsReadOnly(value.Split(',', StringSplitOptions.RemoveEmptyEntries));
    }
}
