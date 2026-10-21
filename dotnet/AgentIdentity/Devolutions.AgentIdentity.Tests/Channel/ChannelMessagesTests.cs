using System.Text;
using System.Text.Json;

using Devolutions.Agent.Channel.V1;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The messages that the authority pushes on an authenticated agent channel stream,
/// CONTRACT.agent-identity.md §7.3 and §7.4.
/// </summary>
public class ChannelMessagesTests
{
    private static readonly IdentityConfig Config = IdentityConfig.Create(5, "https://host/dvls");

    private static readonly Dictionary<string, Func<ServerMessage>> Messages = new()
    {
        ["ConfigUpdate"] = () => ChannelMessages.ConfigUpdate(Config),
        ["RenewRequested"] = () => ChannelMessages.RenewRequested(RenewalRequestReason.Admin),
        ["Reconnect"] = () => ChannelMessages.Reconnect(ReconnectReason.CertificateRotated),
    };

    // The messages that carry a reason, built with the reason given as its integer value.
    private static readonly Dictionary<string, Func<int, ServerMessage>> MessagesWithAReason = new()
    {
        ["RenewRequested"] = reason => ChannelMessages.RenewRequested((RenewalRequestReason)reason),
        ["Reconnect"] = reason => ChannelMessages.Reconnect((ReconnectReason)reason),
    };

    public static TheoryData<string> MessageNames => new(Messages.Keys);

    // CONTRACT.agent-identity.md §1 and §7.3: envelope ids are lowercase hyphenated UUIDs.
    // A push answers no agent message, so it has no correlation_id.
    [Theory]
    [MemberData(nameof(MessageNames))]
    public void MessageHasALowercaseUuidIdAndNoCorrelationId(string message)
    {
        ServerMessage built = Messages[message]();

        Assert.Matches(TestJson.LowercaseUuidPattern, built.Id);
        Assert.False(built.HasCorrelationId);
    }

    // CONTRACT.agent-identity.md §7.3 steps 5 and 7: the agent acknowledges a message by its id,
    // so no two messages share one.
    [Theory]
    [MemberData(nameof(MessageNames))]
    public void EachMessageHasItsOwnId(string message)
    {
        Assert.NotEqual(Messages[message]().Id, Messages[message]().Id);
    }

    // CONTRACT.agent-identity.md §7.3 step 7 and channel.proto: ConfigUpdate carries the config, in the shape of §5.2,
    // as a UTF-8 JSON object.
    [Fact]
    public void ConfigUpdateCarriesTheConfigJson()
    {
        ServerMessage message = ChannelMessages.ConfigUpdate(Config);

        Assert.Equal(ServerMessage.PayloadOneofCase.ConfigUpdate, message.PayloadCase);
        Dictionary<string, JsonElement> config =
            TestJson.Members(Encoding.UTF8.GetBytes(message.ConfigUpdate.ConfigJson));
        Assert.Equal(["agent_channel_url", "revision", "version"], TestJson.Names(config));
        Assert.Equal("1", config["version"].GetRawText());
        Assert.Equal("5", config["revision"].GetRawText());
        Assert.Equal("https://host/dvls", config["agent_channel_url"].GetString());
    }

    // channel.proto: the reason of RenewRequested is "admin" or "rotation";
    // CONTRACT.agent-identity.md §8.3 sends "rotation" at the start of a root rotation.
    [Theory]
    [InlineData(RenewalRequestReason.Admin, "admin")]
    [InlineData(RenewalRequestReason.Rotation, "rotation")]
    public void RenewRequestedCarriesItsReason(RenewalRequestReason reason, string expected)
    {
        ServerMessage message = ChannelMessages.RenewRequested(reason);

        Assert.Equal(ServerMessage.PayloadOneofCase.RenewRequested, message.PayloadCase);
        Assert.Equal(expected, message.RenewRequested.Reason);
    }

    // CONTRACT.agent-identity.md §7.4: the streams of a retired certificate get
    // Reconnect{reason:"certificate_rotated"}.
    [Fact]
    public void ReconnectCarriesItsReason()
    {
        ServerMessage message = ChannelMessages.Reconnect(ReconnectReason.CertificateRotated);

        Assert.Equal(ServerMessage.PayloadOneofCase.Reconnect, message.PayloadCase);
        Assert.Equal("certificate_rotated", message.Reconnect.Reason);
    }

    // Reasons start at 1, so a reason that the host never set is not a valid one,
    // and a value after the last reason is not one either.
    // Framework Design Guidelines: validate enum arguments, and throw the most derived ArgumentException naming them.
    [Theory]
    [InlineData("RenewRequested", 0)]
    [InlineData("RenewRequested", 3)]
    [InlineData("Reconnect", 0)]
    [InlineData("Reconnect", 2)]
    public void MessageRejectsAnUndefinedReason(string message, int reason)
    {
        ArgumentOutOfRangeException exception =
            Assert.Throws<ArgumentOutOfRangeException>(() => MessagesWithAReason[message](reason));

        Assert.Equal("reason", exception.ParamName);
    }
}
