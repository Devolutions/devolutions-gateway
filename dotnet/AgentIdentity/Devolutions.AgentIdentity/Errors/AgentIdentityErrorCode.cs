namespace Devolutions.AgentIdentity;

/// <summary>
/// An error code of the agent-facing protocol.
/// </summary>
/// <remarks>
/// The agent decides from the code whether to retry, to discard a pending enrollment, or to stop using an identity,
/// so each code keeps the meaning and the statuses that <see cref="AgentIdentityErrorCodeExtensions"/> gives it.
/// </remarks>
public enum AgentIdentityErrorCode
{
    // UNTESTED: each value stays the same across releases.
    // Consumers compile the values in, so renumbering a code would change what an existing host sends.
    // When adding a code, give it the next unused value;
    // values start at 1 so that an uninitialized code is not a valid one.

    /// <summary>
    /// The enrollment token is unknown or revoked, or its secret does not match.
    /// </summary>
    TokenInvalid = 1,

    /// <summary>
    /// The enrollment token has created its maximum number of identities.
    /// </summary>
    TokenExhausted = 2,

    /// <summary>
    /// The enrollment token has expired.
    /// </summary>
    TokenExpired = 3,

    /// <summary>
    /// The identity is revoked.
    /// </summary>
    IdentityRevoked = 4,

    /// <summary>
    /// The certificate is not registered, or its identity was deleted.
    /// </summary>
    IdentityUnknown = 5,

    /// <summary>
    /// The certificate has expired, or for a renewal, is beyond its grace.
    /// </summary>
    CertificateExpired = 6,

    /// <summary>
    /// The signature, its parameters, the body digest or the channel proof is invalid, or the nonce was already used.
    /// </summary>
    SignatureInvalid = 7,

    /// <summary>
    /// The signature's <c>created</c> or <c>expires</c> time is outside the accepted window.
    /// </summary>
    ClockSkew = 8,

    /// <summary>
    /// The route, method, body, CSR or metadata is invalid.
    /// </summary>
    InvalidRequest = 9,

    /// <summary>
    /// The server can't serve the request now, because it is overloaded or a part it needs fails.
    /// </summary>
    Unavailable = 10,

    /// <summary>
    /// The CSR of an enrollment names no enrollment URL, or not the presented token's `u`.
    /// </summary>
    TokenUrlMismatch = 11,
}
