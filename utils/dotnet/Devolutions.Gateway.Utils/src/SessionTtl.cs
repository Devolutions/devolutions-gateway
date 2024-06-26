using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(SessionTtlJsonConverter))]
public struct SessionTtl
{
    public UInt64 Minutes { get; private set; }

    public SessionTtl(UInt64 minutes)
    {
        Minutes = minutes;
    }

    public static SessionTtl Unlimited = new SessionTtl(0);

    public bool IsUnlimited() => Minutes == 0;
}