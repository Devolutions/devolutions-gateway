using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(ReusePolicyJsonConverter))]
public struct ReusePolicy
{
    public uint Value { get; internal set; }

    internal ReusePolicy(uint value)
    {
        Value = value;
    }

    public static ReusePolicy Allowed(uint windowInSeconds)
    {
        return new ReusePolicy(windowInSeconds);
    }

    public static ReusePolicy Disallow = new ReusePolicy(0);
}