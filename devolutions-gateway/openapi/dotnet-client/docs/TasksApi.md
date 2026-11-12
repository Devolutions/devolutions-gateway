# Devolutions.Gateway.Client.Api.TasksApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetAiAnalysis**](TasksApi.md#getaianalysis) | **GET** /jet/tasks/recording-ai-analysis/{task_id} | Gets an AI analysis of a recorded session |
| [**StartAiAnalysis**](TasksApi.md#startaianalysis) | **PUT** /jet/tasks/recording-ai-analysis/{task_id} | Starts an AI analysis of a recorded session |

<a id="getaianalysis"></a>
# **GetAiAnalysis**
> AiAnalysisTask GetAiAnalysis (Guid taskId)

Gets an AI analysis of a recorded session

Returns the Task of the analysis: its state, its progress while it runs, its result once it is over, and the tokens it used in every state but `queued`. Tasks are kept forever, across Gateway restarts; an unfinished Task past its deadline is reported as failed.

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
    public class GetAiAnalysisExample
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
            var taskId = "taskId_example";  // Guid | Task ID of the AI analysis

            try
            {
                // Gets an AI analysis of a recorded session
                AiAnalysisTask result = apiInstance.GetAiAnalysis(taskId);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling TasksApi.GetAiAnalysis: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetAiAnalysisWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Gets an AI analysis of a recorded session
    ApiResponse<AiAnalysisTask> response = apiInstance.GetAiAnalysisWithHttpInfo(taskId);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling TasksApi.GetAiAnalysisWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **taskId** | **Guid** | Task ID of the AI analysis |  |

### Return type

[**AiAnalysisTask**](AiAnalysisTask.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/problem+json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The AI analysis Task |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | No AI analysis has this Task ID |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="startaianalysis"></a>
# **StartAiAnalysis**
> AiAnalysisTask StartAiAnalysis (Guid taskId, AiAnalysisRequest aiAnalysisRequest)

Starts an AI analysis of a recorded session

Gateway asks the AI provider what the user did in the session recording, and puts the answer in the session as its log, listed under `artifacts.ai-analysis` in its manifest. The answer is in the `language` of the request, English without one. The work runs in the background as a Task; follow it with `GET /jet/tasks/recording-ai-analysis/{task_id}`.  Sending the same request again returns the same Task and starts nothing new. A new Task for the session starts from scratch, and replaces the earlier AI analysis of the session once its success is recorded, so a session holds at most one; a Task that fails leaves the earlier analysis in place and removes everything it made. A Task fails if it does not start within 2 hours, or, once it runs, after 30 minutes without progress. The API key and the base URL are kept in memory only, until the Task ends; a Gateway restart fails the unfinished Tasks.

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
    public class StartAiAnalysisExample
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
            var taskId = "taskId_example";  // Guid | Task ID, chosen by the caller so it can send the same request again safely
            var aiAnalysisRequest = new AiAnalysisRequest(); // AiAnalysisRequest | AI analysis settings

            try
            {
                // Starts an AI analysis of a recorded session
                AiAnalysisTask result = apiInstance.StartAiAnalysis(taskId, aiAnalysisRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling TasksApi.StartAiAnalysis: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the StartAiAnalysisWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Starts an AI analysis of a recorded session
    ApiResponse<AiAnalysisTask> response = apiInstance.StartAiAnalysisWithHttpInfo(taskId, aiAnalysisRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling TasksApi.StartAiAnalysisWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **taskId** | **Guid** | Task ID, chosen by the caller so it can send the same request again safely |  |
| **aiAnalysisRequest** | [**AiAnalysisRequest**](AiAnalysisRequest.md) | AI analysis settings |  |

### Return type

[**AiAnalysisTask**](AiAnalysisTask.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json, application/problem+json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The same request came in before; nothing new starts |  -  |
| **202** | The AI analysis Task is created and runs in the background |  * Location - Path of the new Task, &#x60;/jet/tasks/recording-ai-analysis/{task_id}&#x60; <br>  |
| **400** | Invalid request body, AI settings or language |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | The session has no recording |  -  |
| **409** | The AI analysis cannot start now |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

