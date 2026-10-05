# Devolutions.Gateway.Client.Api.TasksApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetTask**](TasksApi.md#gettask) | **GET** /jet/tasks/{id} | Gets the status of a background task. |
| [**StartTask**](TasksApi.md#starttask) | **POST** /jet/tasks | Starts a background task. |

<a id="gettask"></a>
# **GetTask**
> TaskInfo GetTask (Guid id)

Gets the status of a background task.

Task records are kept forever, including across Gateway restarts.  This endpoint is unstable: it is only available when `__debug__.enable_unstable` is set.

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
    public class GetTaskExample
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
            var apiInstance = new TasksApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | Task ID

            try
            {
                // Gets the status of a background task.
                TaskInfo result = apiInstance.GetTask(id);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling TasksApi.GetTask: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetTaskWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Gets the status of a background task.
    ApiResponse<TaskInfo> response = apiInstance.GetTaskWithHttpInfo(id);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling TasksApi.GetTaskWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** | Task ID |  |

### Return type

[**TaskInfo**](TaskInfo.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Task status |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | No task with this ID |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="starttask"></a>
# **StartTask**
> TaskInfo StartTask (Object body)

Starts a background task.

The TASK token holds the whole task: its kind, and the payload of that kind. The token is not encrypted, so the request body carries the secrets of the kind: `RecordingAiAnalysisCredentials` for `recording.ai-analysis`.  This endpoint is unstable: it is only available when `__debug__.enable_unstable` is set.

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
    public class StartTaskExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: task_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new TasksApi(httpClient, config, httpClientHandler);
            var body = null;  // Object | Secrets of the task kind, such as `RecordingAiAnalysisCredentials` for `recording.ai-analysis`

            try
            {
                // Starts a background task.
                TaskInfo result = apiInstance.StartTask(body);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling TasksApi.StartTask: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the StartTaskWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Starts a background task.
    ApiResponse<TaskInfo> response = apiInstance.StartTaskWithHttpInfo(body);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling TasksApi.StartTaskWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **body** | **Object** | Secrets of the task kind, such as &#x60;RecordingAiAnalysisCredentials&#x60; for &#x60;recording.ai-analysis&#x60; |  |

### Return type

[**TaskInfo**](TaskInfo.md)

### Authorization

[task_token](../README.md#task_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **202** | Task was accepted and runs in the background |  -  |
| **400** | Invalid task or request body |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **409** | The task target is busy, such as a session that is still recording |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

