using System.Security.Cryptography;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// A clock that reads <see cref="Now"/>, which a test sets.
/// </summary>
internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow()
    {
        return Now;
    }
}

/// <summary>
/// A clock that returns the given instants, one per reading, and then repeats the last one.
/// </summary>
internal sealed class SteppingTimeProvider(params DateTimeOffset[] readings) : TimeProvider
{
    private int _next;

    public override DateTimeOffset GetUtcNow()
    {
        DateTimeOffset reading = readings[Math.Min(_next, readings.Length - 1)];
        _next++;
        return reading;
    }
}

/// <summary>
/// A registry over a dictionary, which records every lookup and can hold lookups until a test releases them.
/// </summary>
internal sealed class FakeCertificateRegistry : ICertificateRegistry
{
    private readonly Dictionary<string, RegisteredCertificate> _certificates = new(StringComparer.Ordinal);

    public List<string> Lookups { get; } = [];

    /// <summary>
    /// A task that every lookup waits for before it answers, when set.
    /// </summary>
    public Task? Gate { get; set; }

    public void Register(string thumbprint, RegisteredCertificate certificate)
    {
        _certificates[thumbprint] = certificate;
    }

    public void Register(
        KeyVector key,
        CertificateStatus status = CertificateStatus.Current,
        bool identityRevoked = false)
    {
        Register(key.Thumbprint, new RegisteredCertificate(key.IdentityId, key.Certificate, status, identityRevoked));
    }

    public void Unregister(string thumbprint)
    {
        _certificates.Remove(thumbprint);
    }

    public async ValueTask<RegisteredCertificate?> FindByThumbprintAsync(
        string thumbprint,
        CancellationToken cancellationToken)
    {
        Lookups.Add(thumbprint);

        if (Gate is { } gate)
        {
            await gate.WaitAsync(cancellationToken);
        }

        return _certificates.GetValueOrDefault(thumbprint);
    }
}

/// <summary>
/// A nonce store over a set, which records every call and can be told to answer that every pair is already recorded.
/// </summary>
internal sealed class RecordingNonceStore : INonceStore
{
    private readonly HashSet<(string KeyId, string Nonce)> _recorded = [];

    public bool AnswerAlreadyRecorded { get; init; }

    public List<(string KeyId, string Nonce, DateTimeOffset RetainUntil)> Calls { get; } = [];

    public ValueTask<bool> TryRecordAsync(
        string keyId,
        string nonce,
        DateTimeOffset retainUntil,
        CancellationToken cancellationToken)
    {
        Calls.Add((keyId, nonce, retainUntil));
        return ValueTask.FromResult(!AnswerAlreadyRecorded && _recorded.Add((keyId, nonce)));
    }
}

/// <summary>
/// A generator whose bytes count up from zero, so that a test knows which bytes each call returns.
/// </summary>
internal sealed class CountingRandomNumberGenerator : RandomNumberGenerator
{
    private byte _next;

    public override void GetBytes(byte[] data)
    {
        GetBytes(data.AsSpan());
    }

    public override void GetBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = _next++;
        }
    }
}

/// <summary>
/// A generator that returns the given bytes in order and fails when asked for more,
/// so that a test controls every random byte the library draws.
/// </summary>
internal sealed class ScriptedRandomNumberGenerator(byte[] bytes) : RandomNumberGenerator
{
    private int _next;

    public override void GetBytes(byte[] data)
    {
        GetBytes(data.AsSpan());
    }

    public override void GetBytes(Span<byte> data)
    {
        if (data.Length > bytes.Length - _next)
        {
            throw new InvalidOperationException("The test supplied fewer random bytes than the library drew.");
        }

        bytes.AsSpan(_next, data.Length).CopyTo(data);
        _next += data.Length;
    }
}
