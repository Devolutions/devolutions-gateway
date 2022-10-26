using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public interface IGatewayClaims
{
    string GetContentType();

    long GetDefaultLifetime()
    {
        return 300;
    }
}