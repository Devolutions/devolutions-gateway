# Devolutions.Gateway.Client.Api.PreflightApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**PostPreflight**](PreflightApi.md#postpreflight) | **POST** /jet/preflight | Performs a batch of preflight operations |

<a id="postpreflight"></a>
# **PostPreflight**
> List&lt;PreflightOutput&gt; PostPreflight (List<PreflightOperation> preflightOperation)

Performs a batch of preflight operations

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
    public class PostPreflightExample
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
            var apiInstance = new PreflightApi(httpClient, config, httpClientHandler);
            var preflightOperation = new List<PreflightOperation>(); // List<PreflightOperation> | 

            try
            {
                // Performs a batch of preflight operations
                List<PreflightOutput> result = apiInstance.PostPreflight(preflightOperation);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling PreflightApi.PostPreflight: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PostPreflightWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Performs a batch of preflight operations
    ApiResponse<List<PreflightOutput>> response = apiInstance.PostPreflightWithHttpInfo(preflightOperation);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling PreflightApi.PostPreflightWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **preflightOperation** | [**List&lt;PreflightOperation&gt;**](PreflightOperation.md) |  |  |

### Return type

[**List&lt;PreflightOutput&gt;**](PreflightOutput.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Preflight outputs |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

