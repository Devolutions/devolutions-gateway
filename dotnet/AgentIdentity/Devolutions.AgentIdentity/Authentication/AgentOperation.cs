namespace Devolutions.AgentIdentity;

/// <summary>
/// An operation that an agent authenticates with a signed request.
/// </summary>
/// <remarks>
/// Each operation has its own <c>tag</c>, covered components and rule for the certificate it accepts,
/// so a signature made for one operation never authenticates another.
/// </remarks>
public enum AgentOperation
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering an operation would change what an existing host asks for.
    // When adding an operation, give it the next unused value;
    // values start at 1 so that an uninitialized operation is not a valid one.

    /// <summary>
    /// <c>POST renew</c>, signed with tag <c>renew</c>.
    /// </summary>
    Renew = 1,

    /// <summary>
    /// <c>POST confirm</c>, signed with tag <c>confirm</c>.
    /// </summary>
    Confirm = 2,

    /// <summary>
    /// <c>POST check-in</c>, signed with tag <c>check-in</c>.
    /// </summary>
    CheckIn = 3,

    /// <summary>
    /// The opening request of an agent channel stream, signed with tag <c>connect</c>.
    /// </summary>
    Connect = 4,
}
