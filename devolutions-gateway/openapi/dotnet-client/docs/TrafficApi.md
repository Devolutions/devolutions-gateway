# Devolutions.Gateway.Client.Api.TrafficApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**AckTrafficEvents**](TrafficApi.md#acktrafficevents) | **POST** /jet/traffic/ack | Acknowledge traffic audit events and remove them from the queue |
| [**ClaimTrafficEvents**](TrafficApi.md#claimtrafficevents) | **POST** /jet/traffic/claim | Claim traffic audit events for processing |

<a id="acktrafficevents"></a>
# **AckTrafficEvents**
> AckResponse AckTrafficEvents (AckRequest ackRequest)

Acknowledge traffic audit events and remove them from the queue

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
    public class AckTrafficEventsExample
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
            var apiInstance = new TrafficApi(httpClient, config, httpClientHandler);
            var ackRequest = new AckRequest(); // AckRequest | Array of event IDs to acknowledge

            try
            {
                // Acknowledge traffic audit events and remove them from the queue
                AckResponse result = apiInstance.AckTrafficEvents(ackRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling TrafficApi.AckTrafficEvents: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the AckTrafficEventsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Acknowledge traffic audit events and remove them from the queue
    ApiResponse<AckResponse> response = apiInstance.AckTrafficEventsWithHttpInfo(ackRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling TrafficApi.AckTrafficEventsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **ackRequest** | [**AckRequest**](AckRequest.md) | Array of event IDs to acknowledge |  |

### Return type

[**AckResponse**](AckResponse.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successfully acknowledged events |  -  |
| **400** | Invalid request body (empty ids array) |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **413** | Payload too large (more than 10,000 IDs) |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="claimtrafficevents"></a>
# **ClaimTrafficEvents**
> List&lt;ClaimedTrafficEvent&gt; ClaimTrafficEvents (int leaseMs, int max)

Claim traffic audit events for processing

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
    public class ClaimTrafficEventsExample
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
            var apiInstance = new TrafficApi(httpClient, config, httpClientHandler);
            var leaseMs = 56;  // int | Lease duration in milliseconds (1000-3600000, default: 300000 = 5 minutes)
            var max = 56;  // int | Maximum number of events to claim (1-1000, default: 100)

            try
            {
                // Claim traffic audit events for processing
                List<ClaimedTrafficEvent> result = apiInstance.ClaimTrafficEvents(leaseMs, max);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling TrafficApi.ClaimTrafficEvents: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the ClaimTrafficEventsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Claim traffic audit events for processing
    ApiResponse<List<ClaimedTrafficEvent>> response = apiInstance.ClaimTrafficEventsWithHttpInfo(leaseMs, max);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling TrafficApi.ClaimTrafficEventsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **leaseMs** | **int** | Lease duration in milliseconds (1000-3600000, default: 300000 &#x3D; 5 minutes) |  |
| **max** | **int** | Maximum number of events to claim (1-1000, default: 100) |  |

### Return type

[**List&lt;ClaimedTrafficEvent&gt;**](ClaimedTrafficEvent.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Successfully claimed traffic events |  -  |
| **400** | Invalid query parameters |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

