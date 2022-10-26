using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(TargetAddrJsonConverter))]
public class TargetAddr
{
    public string Scheme { get; set; }

    public string Host { get; set; }

    public int? Port { get; set; }

    public TargetAddr(string scheme, string host, int port)
    {
        this.Scheme = scheme;
        this.Host = host;
        this.Port = port;
    }

    public TargetAddr(Uri uri)
    {
        this.Scheme = uri.Scheme;
        this.Host = uri.Host;

        if (uri.Port != -1)
        {
            this.Port = uri.Port;
        }
    }

    public static TargetAddr Parse(string repr)
    {
        if (!repr.Contains("://"))
        {
            return new TargetAddr(new Uri($"tcp://{repr}"));
        }

        return new TargetAddr(new Uri(repr));
    }

    public static implicit operator TargetAddr(Uri uri) => new TargetAddr(uri);
    public static implicit operator TargetAddr(string repr) => TargetAddr.Parse(repr);

    public override string? ToString()
    {
        if (this.Port != null)
        {
            return $"{this.Scheme}://{this.Host}:{this.Port}";
        }
        else
        {
            return $"{this.Scheme}://{this.Host}";
        }
    }
}