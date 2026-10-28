using System.Text;
using System.Text.Json;

using Devolutions.Agent.Channel.V1;

namespace Devolutions.Agent.Identity.Authority.Tests;

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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    [Theory]
    [MemberData(nameof(MessageNames))]
    public void MessageHasALowercaseUuidId(string message)
    {
        ServerMessage built = Messages[message]();

        Assert.Matches(TestJson.LowercaseUuidPattern, built.Id);
    }

    // Steps 5 and 7: the agent acknowledges a message by its id, so no two messages share one.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    [Theory]
    [MemberData(nameof(MessageNames))]
    public void EachMessageHasItsOwnId(string message)
    {
        Assert.NotEqual(Messages[message]().Id, Messages[message]().Id);
    }

    // CONTRACT.agent-identity.md §7.3 step 7 and channel.proto: ConfigUpdate carries the config, in the shape of §5.2,
    // as a UTF-8 JSON object.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
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
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-service
    [Theory]
    [InlineData(RenewalRequestReason.Admin, "admin")]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §root-rotation
    [InlineData(RenewalRequestReason.Rotation, "rotation")]
    public void RenewRequestedCarriesItsReason(RenewalRequestReason reason, string expected)
    {
        ServerMessage message = ChannelMessages.RenewRequested(reason);

        Assert.Equal(ServerMessage.PayloadOneofCase.RenewRequested, message.PayloadCase);
        Assert.Equal(expected, message.RenewRequested.Reason);
    }

    // The streams of a retired certificate get Reconnect{reason:"certificate_rotated"}.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
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
    // oracle: spec Framework Design Guidelines §Validating Arguments
    // oracle: spec Framework Design Guidelines §Using Standard Exception Types
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
