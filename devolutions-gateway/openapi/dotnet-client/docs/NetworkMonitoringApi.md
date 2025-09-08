# Devolutions.Gateway.Client.Api.NetworkMonitoringApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**DrainMonitoringLog**](NetworkMonitoringApi.md#drainmonitoringlog) | **POST** /jet/net/monitor/log/drain | Monitors store their results in a temporary log, which is returned here. |
| [**SetMonitoringConfig**](NetworkMonitoringApi.md#setmonitoringconfig) | **POST** /jet/net/monitor/config | Replace the current monitoring configuration with the configuration in the request body. |

<a id="drainmonitoringlog"></a>
# **DrainMonitoringLog**
> MonitoringLogResponse DrainMonitoringLog ()

Monitors store their results in a temporary log, which is returned here.

Once the log is downloaded, gateway purges it from memory.

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
    public class DrainMonitoringLogExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new NetworkMonitoringApi(httpClient, config, httpClientHandler);

            try
            {
                // Monitors store their results in a temporary log, which is returned here.
                MonitoringLogResponse result = apiInstance.DrainMonitoringLog();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling NetworkMonitoringApi.DrainMonitoringLog: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the DrainMonitoringLogWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Monitors store their results in a temporary log, which is returned here.
    ApiResponse<MonitoringLogResponse> response = apiInstance.DrainMonitoringLogWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling NetworkMonitoringApi.DrainMonitoringLogWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**MonitoringLogResponse**](MonitoringLogResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Log was flushed and returned in the response body |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="setmonitoringconfig"></a>
# **SetMonitoringConfig**
> void SetMonitoringConfig (MonitorsConfig monitorsConfig)

Replace the current monitoring configuration with the configuration in the request body.

Changes take effect immediately: - Starts any monitors newly defined in the payload. - Stops any currently running monitors that are omitted from the payload.  Note: The configuration is not persisted across process restarts.

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
    public class SetMonitoringConfigExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new NetworkMonitoringApi(httpClient, config, httpClientHandler);
            var monitorsConfig = new MonitorsConfig(); // MonitorsConfig | JSON object containing a list of monitors

            try
            {
                // Replace the current monitoring configuration with the configuration in the request body.
                apiInstance.SetMonitoringConfig(monitorsConfig);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling NetworkMonitoringApi.SetMonitoringConfig: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the SetMonitoringConfigWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Replace the current monitoring configuration with the configuration in the request body.
    apiInstance.SetMonitoringConfigWithHttpInfo(monitorsConfig);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling NetworkMonitoringApi.SetMonitoringConfigWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **monitorsConfig** | [**MonitorsConfig**](MonitorsConfig.md) | JSON object containing a list of monitors |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | New configuration was accepted |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error while starting monitors |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

