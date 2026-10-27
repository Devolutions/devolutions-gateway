namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Records the nonces of accepted signatures, so that each signature is accepted at most once.
/// </summary>
/// <remarks>
/// The host implements it over its own storage.
/// Request authentication records a nonce only after the signature and the body digest verify,
/// so requests that fail verification cannot fill the store.
/// </remarks>
public interface INonceStore
{
    /// <summary>
    /// Records a nonce for a key unless the pair is already recorded, as one atomic operation.
    /// </summary>
    /// <param name="keyId">The <c>keyid</c> of the signature, which is the thumbprint of its certificate.</param>
    /// <param name="nonce">The <c>nonce</c> of the signature, as its canonical base64url text.</param>
    /// <param name="retainUntil">
    /// The instant until which the store keeps the pair.
    /// It falls 60 s after the last instant at which the signature could be accepted again,
    /// a margin for the time that this call takes,
    /// so a store whose calls complete within 60 s may discard the pair from then on.
    /// </param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>True when this call recorded the pair; false when the pair was already recorded.</returns>
    ValueTask<bool> TryRecordAsync(
        string keyId,
        string nonce,
        DateTimeOffset retainUntil,
        CancellationToken cancellationToken);
}
