# Devolutions.Gateway.Client.Api.DiagnosticsApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetClockDiagnostic**](DiagnosticsApi.md#getclockdiagnostic) | **GET** /jet/diagnostics/clock | Retrieves server&#39;s clock in order to diagnose clock drifting. |
| [**GetConfigurationDiagnostic**](DiagnosticsApi.md#getconfigurationdiagnostic) | **GET** /jet/diagnostics/configuration | Retrieves configuration. |
| [**GetLogs**](DiagnosticsApi.md#getlogs) | **GET** /jet/diagnostics/logs | Retrieves latest logs. |

<a name="getclockdiagnostic"></a>
# **GetClockDiagnostic**
> ClockDiagnostic GetClockDiagnostic ()

Retrieves server's clock in order to diagnose clock drifting.

Retrieves server's clock in order to diagnose clock drifting.  This route is not secured by access token. Indeed, this route is used to retrieve server's clock when diagnosing clock drifting. If there is clock drift, token validation will fail because claims such as `nbf` will then be invalid, and thus prevent the clock drift diagnosis.

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class GetClockDiagnosticExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            var apiInstance = new DiagnosticsApi(config);

            try
            {
                // Retrieves server's clock in order to diagnose clock drifting.
                ClockDiagnostic result = apiInstance.GetClockDiagnostic();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DiagnosticsApi.GetClockDiagnostic: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetClockDiagnosticWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieves server's clock in order to diagnose clock drifting.
    ApiResponse<ClockDiagnostic> response = apiInstance.GetClockDiagnosticWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DiagnosticsApi.GetClockDiagnosticWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**ClockDiagnostic**](ClockDiagnostic.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Server&#39;s clock |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a name="getconfigurationdiagnostic"></a>
# **GetConfigurationDiagnostic**
> ConfigDiagnostic GetConfigurationDiagnostic ()

Retrieves configuration.

Retrieves configuration.

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class GetConfigurationDiagnosticExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new DiagnosticsApi(config);

            try
            {
                // Retrieves configuration.
                ConfigDiagnostic result = apiInstance.GetConfigurationDiagnostic();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DiagnosticsApi.GetConfigurationDiagnostic: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetConfigurationDiagnosticWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieves configuration.
    ApiResponse<ConfigDiagnostic> response = apiInstance.GetConfigurationDiagnosticWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DiagnosticsApi.GetConfigurationDiagnosticWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**ConfigDiagnostic**](ConfigDiagnostic.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Service configuration diagnostic (including version) |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a name="getlogs"></a>
# **GetLogs**
> string GetLogs ()

Retrieves latest logs.

Retrieves latest logs.

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class GetLogsExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new DiagnosticsApi(config);

            try
            {
                // Retrieves latest logs.
                string result = apiInstance.GetLogs();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DiagnosticsApi.GetLogs: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetLogsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieves latest logs.
    ApiResponse<string> response = apiInstance.GetLogsWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DiagnosticsApi.GetLogsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

**string**

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Latest logs |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to retrieve logs |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

