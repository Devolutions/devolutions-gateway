using System.Text;

using Devolutions.Agent.Channel.V1;

using ConfigUpdatePayload = Devolutions.Agent.Channel.V1.ConfigUpdate;
using ReconnectPayload = Devolutions.Agent.Channel.V1.Reconnect;
using RenewRequestedPayload = Devolutions.Agent.Channel.V1.RenewRequested;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Builds the messages that the authority pushes to the agent on an agent channel stream.
/// </summary>
/// <remarks>
/// The host sends them only on an authenticated stream, after its <c>Welcome</c>,
/// since nothing is pushed before the agent signs the stream's challenge.
/// Each message has a fresh <c>id</c>, a lowercase hyphenated UUID,
/// which the agent's <c>Ack</c> carries as its <c>correlation_id</c>.
/// A push is an optimization, since <c>Hello</c> and <c>Welcome</c> reconcile the state at every connection.
/// </remarks>
public static class ChannelMessages
{
    /// <summary>
    /// Builds a <c>ConfigUpdate</c>, whose <c>config_json</c> is the identity's config as a JSON object.
    /// </summary>
    /// <remarks>
    /// The host sends it after the <c>Welcome</c> when the identity's config has a higher revision than the one in
    /// <c>applied_state_versions["config"]</c> of the <c>Hello</c>,
    /// and on each live stream of the identity when its config changes.
    /// </remarks>
    /// <param name="config">The identity's config.</param>
    /// <exception cref="ArgumentNullException"><paramref name="config"/> is null.</exception>
    public static ServerMessage ConfigUpdate(IdentityConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return new ServerMessage
        {
            Id = NewId(),
            ConfigUpdate = new ConfigUpdatePayload { ConfigJson = Encoding.UTF8.GetString(config.Utf8Json) },
        };
    }

    /// <summary>
    /// Builds a <c>RenewRequested</c>, which asks the agent to renew its certificate.
    /// </summary>
    /// <remarks>
    /// While the identity's request-renewal flag is set, the host sends it after the <c>Welcome</c> of every stream
    /// that the identity opens, until the identity confirms a certificate issued after the flag was set.
    /// </remarks>
    /// <param name="reason">Why the authority asks for the renewal.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is not a defined reason.</exception>
    public static ServerMessage RenewRequested(RenewalRequestReason reason)
    {
        string wireReason = reason switch
        {
            RenewalRequestReason.Admin => "admin",
            RenewalRequestReason.Rotation => "rotation",
            _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Not a defined renewal request reason."),
        };

        return new ServerMessage { Id = NewId(), RenewRequested = new RenewRequestedPayload { Reason = wireReason } };
    }

    /// <summary>
    /// Builds a <c>Reconnect</c>, which asks the agent to open a new stream and then close this one.
    /// </summary>
    /// <remarks>
    /// When a confirmation retires the certificate that opened a stream,
    /// the host sends it on that stream with <see cref="ReconnectReason.CertificateRotated"/>,
    /// and closes the stream with status <c>OK</c> 60 s later if it is still open.
    /// </remarks>
    /// <param name="reason">Why the authority asks for a new stream.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is not a defined reason.</exception>
    public static ServerMessage Reconnect(ReconnectReason reason)
    {
        string wireReason = reason switch
        {
            ReconnectReason.CertificateRotated => "certificate_rotated",
            _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Not a defined reconnect reason."),
        };

        return new ServerMessage { Id = NewId(), Reconnect = new ReconnectPayload { Reason = wireReason } };
    }

    private static string NewId()
    {
        return Guid.NewGuid().ToString("D");
    }
}
