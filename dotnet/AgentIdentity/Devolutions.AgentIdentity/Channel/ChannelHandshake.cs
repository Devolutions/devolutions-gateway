namespace Devolutions.AgentIdentity;

/// <summary>
/// The timing of the handshake that authenticates an agent channel stream.
/// </summary>
public static class ChannelHandshake
{
    /// <summary>
    /// How long the agent has to answer the challenge after the opening request is verified: 10 seconds.
    /// </summary>
    /// <remarks>
    /// When no message arrives in that time, the host calls <see cref="ChannelOpening.HelloTimedOutAsync"/>
    /// and closes the stream with its error.
    /// <see cref="ChannelOpening.VerifyHelloAsync"/> also fails a message that it reads later than that,
    /// so a late timer cannot let one through.
    /// </remarks>
    public static TimeSpan HelloTimeout { get; } = TimeSpan.FromSeconds(10);
}
