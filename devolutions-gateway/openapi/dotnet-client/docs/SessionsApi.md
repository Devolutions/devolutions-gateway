# Devolutions.Gateway.Client.Api.SessionsApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetSessions**](SessionsApi.md#getsessions) | **GET** /jet/sessions | Lists running sessions |
| [**TerminateSession**](SessionsApi.md#terminatesession) | **POST** /jet/session/{id}/terminate | Terminate forcefully a running session |

<a name="getsessions"></a>
# **GetSessions**
> List&lt;SessionInfo&gt; GetSessions ()

Lists running sessions

Lists running sessions

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class GetSessionsExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new SessionsApi(config);

            try
            {
                // Lists running sessions
                List<SessionInfo> result = apiInstance.GetSessions();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling SessionsApi.GetSessions: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetSessionsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Lists running sessions
    ApiResponse<List<SessionInfo>> response = apiInstance.GetSessionsWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling SessionsApi.GetSessionsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**List&lt;SessionInfo&gt;**](SessionInfo.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Running sessions |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a name="terminatesession"></a>
# **TerminateSession**
> void TerminateSession (Guid id)

Terminate forcefully a running session

Terminate forcefully a running session

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class TerminateSessionExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new SessionsApi(config);
            var id = "id_example";  // Guid | Session / association ID of the session to terminate

            try
            {
                // Terminate forcefully a running session
                apiInstance.TerminateSession(id);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling SessionsApi.TerminateSession: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the TerminateSessionWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Terminate forcefully a running session
    apiInstance.TerminateSessionWithHttpInfo(id);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling SessionsApi.TerminateSessionWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** | Session / association ID of the session to terminate |  |

### Return type

void (empty response body)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Session terminated successfully |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | No running session found with provided ID |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

