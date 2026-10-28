namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The metadata keys through which an agent reports its key storage (CONTRACT.agent-identity.md §3.1).
/// </summary>
/// <remarks>
/// The agent reports both without proof, so an authority may use them to choose a key storage policy,
/// but never refuses a request because of them.
/// </remarks>
public static class AgentMetadataKeys
{
    /// <summary>
    /// The name of the key storage holding the key that the request carries or that signs it,
    /// one of <see cref="KeyStorageNames"/> or a name that the contract added later.
    /// </summary>
    public const string KeyStorage = "key_storage";

    /// <summary>
    /// The names of the key storages available on the device, joined with commas,
    /// which <see cref="KeyStorageNames.ParseAvailable"/> reads.
    /// </summary>
    public const string KeyStorageAvailable = "key_storage_available";
}
