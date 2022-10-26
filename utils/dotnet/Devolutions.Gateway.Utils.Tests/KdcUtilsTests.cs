using System.Text.Json;

namespace Devolutions.Gateway.Utils.Tests;

public class KdcUtilsTests
{
    [Fact]
    public void BuildProxyUrl()
    {
        Uri gatewayBaseUrl = new Uri("https://my.gateway.ninja:7171");
        string kdcToken = "abc.def.ghi";
        Uri expected = new Uri("https://my.gateway.ninja:7171/jet/KdcProxy/abc.def.ghi");

        Uri result = KdcUtils.BuildProxyUrl(gatewayBaseUrl, kdcToken);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void BuildProxyUrlWithoutTrailingSlash()
    {
        Uri gatewayBaseUrl = new Uri("https://my.gateway.ninja:7171/reverse/proxy/to/gateway");
        string kdcToken = "abc.def.ghi";
        Uri expected = new Uri("https://my.gateway.ninja:7171/reverse/proxy/to/gateway/jet/KdcProxy/abc.def.ghi");

        Uri result = KdcUtils.BuildProxyUrl(gatewayBaseUrl, kdcToken);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void BuildProxyUrlWithTrailingSlash()
    {
        Uri gatewayBaseUrl = new Uri("https://my.gateway.ninja:7171/reverse/proxy/to/gateway/");
        string kdcToken = "abc.def.ghi";
        Uri expected = new Uri("https://my.gateway.ninja:7171/reverse/proxy/to/gateway/jet/KdcProxy/abc.def.ghi");

        Uri result = KdcUtils.BuildProxyUrl(gatewayBaseUrl, kdcToken);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ToRegistryFormat()
    {
        Uri proxyUrl = new Uri("https://my.gateway.ninja:7171/jet/KdcProxy/abc.def.ghi");
        string expected = "<https my.gateway.ninja:7171:jet/KdcProxy/abc.def.ghi />";

        string result = KdcUtils.ToRegistryFormat(proxyUrl);
        Assert.Equal(expected, result);
    }
}