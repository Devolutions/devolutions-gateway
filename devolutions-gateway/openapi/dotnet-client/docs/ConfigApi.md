# Devolutions.Gateway.Client.Api.ConfigApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**PatchConfig**](ConfigApi.md#patchconfig) | **PATCH** /jet/config | Modifies configuration |

<a name="patchconfig"></a>
# **PatchConfig**
> void PatchConfig (ConfigPatch configPatch)

Modifies configuration

Modifies configuration 

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class PatchConfigExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new ConfigApi(config);
            var configPatch = new ConfigPatch(); // ConfigPatch | JSON-encoded configuration patch

            try
            {
                // Modifies configuration
                apiInstance.PatchConfig(configPatch);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling ConfigApi.PatchConfig: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PatchConfigWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Modifies configuration
    apiInstance.PatchConfigWithHttpInfo(configPatch);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling ConfigApi.PatchConfigWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **configPatch** | [**ConfigPatch**](ConfigPatch.md) | JSON-encoded configuration patch |  |

### Return type

void (empty response body)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Configuration has been patched with success |  -  |
| **400** | Bad patch request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to patch configuration |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

