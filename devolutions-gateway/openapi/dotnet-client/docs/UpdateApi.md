# Devolutions.Gateway.Client.Api.UpdateApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**TriggerUpdate**](UpdateApi.md#triggerupdate) | **POST** /jet/update | Triggers Devolutions Gateway update process. |

<a id="triggerupdate"></a>
# **TriggerUpdate**
> Object TriggerUpdate (string version)

Triggers Devolutions Gateway update process.

This is done via updating `Agent/update.json` file, which is then read by Devolutions Agent when changes are detected. If the version written to `update.json` is indeed higher than the currently installed version, Devolutions Agent will proceed with the update process.

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class TriggerUpdateExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new UpdateApi(httpClient, config, httpClientHandler);
            var version = "version_example";  // string | The version to install; use 'latest' for the latest version, or 'w.x.y.z' for a specific version

            try
            {
                // Triggers Devolutions Gateway update process.
                Object result = apiInstance.TriggerUpdate(version);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling UpdateApi.TriggerUpdate: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the TriggerUpdateWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Triggers Devolutions Gateway update process.
    ApiResponse<Object> response = apiInstance.TriggerUpdateWithHttpInfo(version);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling UpdateApi.TriggerUpdateWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **version** | **string** | The version to install; use &#39;latest&#39; for the latest version, or &#39;w.x.y.z&#39; for a specific version |  |

### Return type

**Object**

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Update request has been processed successfully |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Agent updater service is malfunctioning |  -  |
| **503** | Agent updater service is unavailable |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

