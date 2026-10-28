namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// What the authority does with an enroll request.
/// </summary>
public enum EnrollmentOutcome
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering an outcome would change what an existing host does.
    // When adding an outcome, give it the next unused value;
    // values start at 1 so that an uninitialized outcome is not a valid one.

    /// <summary>
    /// Create a new identity under <see cref="EnrollmentDecision.NewIdentityId"/>, which counts one use of the token.
    /// </summary>
    CreateIdentity = 1,

    /// <summary>
    /// Return <see cref="EnrollmentDecision.ExistingIdentityId"/> with its current certificate chain,
    /// so that a device recovers a lost enrollment response.
    /// </summary>
    /// <remarks>
    /// The replay counts no use of the token and changes no state of the identity, such as its metadata,
    /// because the CSR proves past possession of the key, not current possession.
    /// </remarks>
    ReturnExistingIdentity = 2,

    /// <summary>
    /// Refuse the request with <see cref="EnrollmentDecision.Error"/>.
    /// </summary>
    Reject = 3,
}
