namespace Devolutions.AgentIdentity;

/// <summary>
/// The timing of the handshake that authenticates an agent channel stream.
/// </summary>
public static class ChannelHandshake
{
    /// <summary>
    /// How long the host waits for the first agent message after it sends the challenge: 10 seconds.
    /// </summary>
    /// <remarks>
    /// When no message arrives in that time, the host calls <see cref="ChannelOpening.HelloTimedOut"/>
    /// and closes the stream with its error.
    /// </remarks>
    public static TimeSpan HelloTimeout { get; } = TimeSpan.FromSeconds(10);
}
