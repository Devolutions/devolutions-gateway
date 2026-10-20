namespace Devolutions.AgentIdentity;

/// <summary>
/// Why the authority asks the agent to replace an agent channel stream, as a <c>Reconnect</c> message says.
/// </summary>
public enum ReconnectReason
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering a reason would change what an existing host sends.
    // When adding a reason, give it the next unused value;
    // values start at 1 so that an uninitialized reason is not a valid one.

    /// <summary>
    /// A confirmation retired the certificate that opened the stream: <c>certificate_rotated</c>.
    /// </summary>
    CertificateRotated = 1,
}
