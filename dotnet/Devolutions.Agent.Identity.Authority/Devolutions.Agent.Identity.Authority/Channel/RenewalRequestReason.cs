namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Why the authority asks an identity to renew its certificate, as a <c>RenewRequested</c> message says.
/// </summary>
public enum RenewalRequestReason
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering a reason would change what an existing host sends.
    // When adding a reason, give it the next unused value;
    // values start at 1 so that an uninitialized reason is not a valid one.

    /// <summary>
    /// An administrator asked for the renewal: <c>admin</c>.
    /// </summary>
    Admin = 1,

    /// <summary>
    /// A root rotation started while the identity holds a certificate from the old root: <c>rotation</c>.
    /// </summary>
    Rotation = 2,
}
