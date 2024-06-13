using System.Text.Json;

namespace Devolutions.Gateway.Utils.Tests;

public class TargetAddrTests
{
    [Fact]
    public void Smoke()
    {
        TargetAddr addr = new TargetAddr("tcp", "devolutions.net", 443);
        Assert.Equal("tcp", addr.Scheme);
        Assert.Equal("devolutions.net", addr.Host);
        Assert.Equal(443, addr.Port);
        Assert.Equal("tcp://devolutions.net:443", addr.ToString());
    }

    [Fact]
    public void NegativePortIsIgnored()
    {
        TargetAddr addr = new TargetAddr("tcp", "devolutions.net", -1);
        Assert.Equal("tcp", addr.Scheme);
        Assert.Equal("devolutions.net", addr.Host);
        Assert.Null(addr.Port);
    }

    [Fact]
    public void TooBigPortIsIgnored()
    {
        TargetAddr addr = new TargetAddr("tcp", "devolutions.net", 65539);
        Assert.Equal("tcp", addr.Scheme);
        Assert.Equal("devolutions.net", addr.Host);
        Assert.Null(addr.Port);
    }
}