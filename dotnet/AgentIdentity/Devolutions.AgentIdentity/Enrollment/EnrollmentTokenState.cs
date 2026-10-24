namespace Devolutions.AgentIdentity;

/// <summary>
/// The stored state of the enrollment token that an enroll request presents.
/// </summary>
/// <remarks>
/// None of it changes after the token is created, except the count of identities it created and its revocation.
/// </remarks>
public sealed class EnrollmentTokenState
{
    /// <summary>
    /// Creates the state of a token.
    /// </summary>
    /// <param name="revoked">Whether the token was revoked.</param>
    /// <param name="productBaseUrl">
    /// The token's <c>u</c>, the product base URL that <see cref="EnrollmentToken.ProductBaseUrl"/> gave when the token
    /// was created.
    /// </param>
    /// <param name="expiresAt">The instant from which the token is expired.</param>
    /// <param name="maxUses">The number of identities that the token may create.</param>
    /// <param name="identitiesCreated">The number of identities that the token has created.</param>
    /// <exception cref="ArgumentNullException"><paramref name="productBaseUrl"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maxUses"/> or <paramref name="identitiesCreated"/> is negative.
    /// </exception>
    public EnrollmentTokenState(
        bool revoked,
        string productBaseUrl,
        DateTimeOffset expiresAt,
        int maxUses,
        int identitiesCreated)
    {
        ArgumentNullException.ThrowIfNull(productBaseUrl);
        ArgumentOutOfRangeException.ThrowIfNegative(maxUses);
        ArgumentOutOfRangeException.ThrowIfNegative(identitiesCreated);

        Revoked = revoked;
        ProductBaseUrl = productBaseUrl;
        ExpiresAt = expiresAt;
        MaxUses = maxUses;
        IdentitiesCreated = identitiesCreated;
    }

    /// <summary>
    /// Whether the token was revoked.
    /// </summary>
    /// <remarks>
    /// A revoked token keeps its secret hash,
    /// so that a device can still recover the enrollment response of an identity that the token created.
    /// </remarks>
    public bool Revoked { get; }

    /// <summary>
    /// The token's <c>u</c>, which the CSR of an enrollment must name, without trailing slashes,
    /// and which every certificate of the identities the token creates names (CONTRACT.agent-identity.md §4).
    /// </summary>
    public string ProductBaseUrl { get; }

    /// <summary>
    /// The instant from which the token is expired.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    /// The number of identities that the token may create.
    /// </summary>
    public int MaxUses { get; }

    /// <summary>
    /// The number of identities that the token has created.
    /// </summary>
    /// <remarks>
    /// Only the creation of a new identity counts; a replay, a failed enrollment and any later operation never do.
    /// </remarks>
    public int IdentitiesCreated { get; }
}
