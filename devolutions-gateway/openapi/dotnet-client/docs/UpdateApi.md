# Devolutions.Gateway.Client.Api.UpdateApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetUpdateProducts**](UpdateApi.md#getupdateproducts) | **GET** /jet/update | Retrieve the currently installed version of each Devolutions product. |
| [**GetUpdateSchedule**](UpdateApi.md#getupdateschedule) | **GET** /jet/update/schedule | Retrieve the current Devolutions Agent auto-update schedule. |
| [**SetUpdateSchedule**](UpdateApi.md#setupdateschedule) | **POST** /jet/update/schedule | Set the Devolutions Agent auto-update schedule. |
| [**TriggerUpdate**](UpdateApi.md#triggerupdate) | **POST** /jet/update | Trigger an update for one or more Devolutions products. |

<a id="getupdateproducts"></a>
# **GetUpdateProducts**
> GetUpdateProductsResponse GetUpdateProducts ()

Retrieve the currently installed version of each Devolutions product.

Reads `update_status.json`, which is written by the Devolutions Agent on startup and refreshed after every update run.  When the file does not exist (agent not installed or is an older version), the endpoint returns HTTP 503 because updater status is unavailable.

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
    public class GetUpdateProductsExample
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

            try
            {
                // Retrieve the currently installed version of each Devolutions product.
                GetUpdateProductsResponse result = apiInstance.GetUpdateProducts();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling UpdateApi.GetUpdateProducts: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetUpdateProductsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieve the currently installed version of each Devolutions product.
    ApiResponse<GetUpdateProductsResponse> response = apiInstance.GetUpdateProductsWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling UpdateApi.GetUpdateProductsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**GetUpdateProductsResponse**](GetUpdateProductsResponse.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Installed product versions |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to read agent status file |  -  |
| **503** | Agent updater service is unavailable |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="getupdateschedule"></a>
# **GetUpdateSchedule**
> GetUpdateScheduleResponse GetUpdateSchedule ()

Retrieve the current Devolutions Agent auto-update schedule.

Reads the `Schedule` field from `update_status.json`.  When the field is absent the response contains zeroed defaults (`Enabled: false`, interval `0`, window start `0`, no products).

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
    public class GetUpdateScheduleExample
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

            try
            {
                // Retrieve the current Devolutions Agent auto-update schedule.
                GetUpdateScheduleResponse result = apiInstance.GetUpdateSchedule();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling UpdateApi.GetUpdateSchedule: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetUpdateScheduleWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieve the current Devolutions Agent auto-update schedule.
    ApiResponse<GetUpdateScheduleResponse> response = apiInstance.GetUpdateScheduleWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling UpdateApi.GetUpdateScheduleWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**GetUpdateScheduleResponse**](GetUpdateScheduleResponse.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Current auto-update schedule |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to read agent status file |  -  |
| **503** | Agent updater service is unavailable |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="setupdateschedule"></a>
# **SetUpdateSchedule**
> Object SetUpdateSchedule (SetUpdateScheduleRequest setUpdateScheduleRequest)

Set the Devolutions Agent auto-update schedule.

Writes the `Schedule` field into `update.json`.  The agent watches this file and applies the new schedule immediately, then persists it to `agent.json`.  All other fields in `update.json` are preserved; the `VersionMinor` field is reset to the minor version this gateway build understands so the agent does not see an unknown future version.

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
    public class SetUpdateScheduleExample
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
            var setUpdateScheduleRequest = new SetUpdateScheduleRequest(); // SetUpdateScheduleRequest | 

            try
            {
                // Set the Devolutions Agent auto-update schedule.
                Object result = apiInstance.SetUpdateSchedule(setUpdateScheduleRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling UpdateApi.SetUpdateSchedule: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the SetUpdateScheduleWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Set the Devolutions Agent auto-update schedule.
    ApiResponse<Object> response = apiInstance.SetUpdateScheduleWithHttpInfo(setUpdateScheduleRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling UpdateApi.SetUpdateScheduleWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **setUpdateScheduleRequest** | [**SetUpdateScheduleRequest**](SetUpdateScheduleRequest.md) |  |  |

### Return type

**Object**

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Auto-update schedule applied |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to write update manifest |  -  |
| **503** | Agent updater service is unavailable |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="triggerupdate"></a>
# **TriggerUpdate**
> Object TriggerUpdate (string? version = null, UpdateRequestSchema? updateRequestSchema = null)

Trigger an update for one or more Devolutions products.

Writes the requested version(s) into `Agent/update.json`, which is watched by Devolutions Agent. When a requested version is higher than the installed version the agent proceeds with the update.  **Body form** (preferred): pass a JSON body with a `Products` map.  **Query-param form** (legacy, gateway-only): `POST /jet/update?version=latest`. This form updates only the Gateway product and is kept for backward compatibility.  Both forms cannot be used simultaneously; doing so returns HTTP 400.

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
            var version = "version_example";  // string? | Gateway-only target version; use the request body for multi-product updates (optional) 
            var updateRequestSchema = new UpdateRequestSchema?(); // UpdateRequestSchema? | Products and target versions to update (optional) 

            try
            {
                // Trigger an update for one or more Devolutions products.
                Object result = apiInstance.TriggerUpdate(version, updateRequestSchema);
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
    // Trigger an update for one or more Devolutions products.
    ApiResponse<Object> response = apiInstance.TriggerUpdateWithHttpInfo(version, updateRequestSchema);
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
| **version** | **string?** | Gateway-only target version; use the request body for multi-product updates | [optional]  |
| **updateRequestSchema** | [**UpdateRequestSchema?**](UpdateRequestSchema?.md) | Products and target versions to update | [optional]  |

### Return type

**Object**

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Update request accepted |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to write update manifest |  -  |
| **503** | Agent updater service is unavailable |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

