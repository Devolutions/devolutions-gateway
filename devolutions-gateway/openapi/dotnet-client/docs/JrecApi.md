# Devolutions.Gateway.Client.Api.JrecApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**DeleteManyRecordings**](JrecApi.md#deletemanyrecordings) | **DELETE** /jet/jrec/delete | Mass-deletes recordings stored on this instance |
| [**DeleteRecording**](JrecApi.md#deleterecording) | **DELETE** /jet/jrec/delete/{id} | Deletes a recording stored on this instance |
| [**ListRecordings**](JrecApi.md#listrecordings) | **GET** /jet/jrec/list | Lists all recordings stored on this instance |
| [**PullRecordingFile**](JrecApi.md#pullrecordingfile) | **GET** /jet/jrec/pull/{id}/{filename} | Retrieves a recording file for a given session |
| [**PullRecordingSession**](JrecApi.md#pullrecordingsession) | **GET** /jet/jrec/pull/{id} | Downloads an entire recorded session as a ZIP archive |
| [**SearchRecordings**](JrecApi.md#searchrecordings) | **POST** /jet/jrec/search | Searches the &#x60;.slog&#x60; artifacts, such as AI analysis logs, of recordings stored on this instance |

<a id="deletemanyrecordings"></a>
# **DeleteManyRecordings**
> DeleteManyResult DeleteManyRecordings (List<Guid> requestBody)

Mass-deletes recordings stored on this instance

If you try to delete more than 50,000 recordings at once, you should split the list into multiple requests. Bigger payloads will be rejected with 413 Payload Too Large.  The request processing consist in 1) checking if one of the recording is active, 2) counting the number of recordings not found on this instance.  When a recording is not found on this instance, a counter is incremented. This number is returned as part of the response. You may use this information to detect anomalies on your side. For instance, this suggests the list of recordings on your side is out of date, and you may want re-index.

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
    public class DeleteManyRecordingsExample
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
            var apiInstance = new JrecApi(httpClient, config, httpClientHandler);
            var requestBody = new List<Guid>(); // List<Guid> | JSON-encoded list of session IDs

            try
            {
                // Mass-deletes recordings stored on this instance
                DeleteManyResult result = apiInstance.DeleteManyRecordings(requestBody);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrecApi.DeleteManyRecordings: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the DeleteManyRecordingsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Mass-deletes recordings stored on this instance
    ApiResponse<DeleteManyResult> response = apiInstance.DeleteManyRecordingsWithHttpInfo(requestBody);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrecApi.DeleteManyRecordingsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **requestBody** | [**List&lt;Guid&gt;**](Guid.md) | JSON-encoded list of session IDs |  |

### Return type

[**DeleteManyResult**](DeleteManyResult.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Mass recording deletion task was successfully started |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **409** | A recording is still ongoing and can&#39;t be deleted yet (nothing is deleted) |  -  |
| **413** | Request payload is too large |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="deleterecording"></a>
# **DeleteRecording**
> void DeleteRecording (Guid id)

Deletes a recording stored on this instance

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
    public class DeleteRecordingExample
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
            var apiInstance = new JrecApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | Recorded session ID

            try
            {
                // Deletes a recording stored on this instance
                apiInstance.DeleteRecording(id);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrecApi.DeleteRecording: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the DeleteRecordingWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Deletes a recording stored on this instance
    apiInstance.DeleteRecordingWithHttpInfo(id);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrecApi.DeleteRecordingWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** | Recorded session ID |  |

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
| **200** | Recording matching the ID in the path has been deleted |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | The specified recording was not found |  -  |
| **409** | The recording is still ongoing and can&#39;t be deleted yet |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="listrecordings"></a>
# **ListRecordings**
> List&lt;Guid&gt; ListRecordings (bool active)

Lists all recordings stored on this instance

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
    public class ListRecordingsExample
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
            var apiInstance = new JrecApi(httpClient, config, httpClientHandler);
            var active = true;  // bool | When true, only the active recordings are returned

            try
            {
                // Lists all recordings stored on this instance
                List<Guid> result = apiInstance.ListRecordings(active);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrecApi.ListRecordings: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the ListRecordingsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Lists all recordings stored on this instance
    ApiResponse<List<Guid>> response = apiInstance.ListRecordingsWithHttpInfo(active);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrecApi.ListRecordingsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **active** | **bool** | When true, only the active recordings are returned |  |

### Return type

**List<Guid>**

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of recordings on this Gateway instance |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="pullrecordingfile"></a>
# **PullRecordingFile**
> FileParameter PullRecordingFile (Guid id, string filename)

Retrieves a recording file for a given session

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
    public class PullRecordingFileExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: jrec_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new JrecApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | Recorded session ID
            var filename = "filename_example";  // string | Name of recording file to retrieve

            try
            {
                // Retrieves a recording file for a given session
                FileParameter result = apiInstance.PullRecordingFile(id, filename);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrecApi.PullRecordingFile: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PullRecordingFileWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieves a recording file for a given session
    ApiResponse<FileParameter> response = apiInstance.PullRecordingFileWithHttpInfo(id, filename);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrecApi.PullRecordingFileWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** | Recorded session ID |  |
| **filename** | **string** | Name of recording file to retrieve |  |

### Return type

[**FileParameter**](FileParameter.md)

### Authorization

[jrec_token](../README.md#jrec_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Recording file |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | File not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="pullrecordingsession"></a>
# **PullRecordingSession**
> FileParameter PullRecordingSession (Guid id)

Downloads an entire recorded session as a ZIP archive

The archive always contains `recording.json` and every clip listed in that manifest that is present on disk. A single-clip session is still returned as a ZIP so callers can use one download contract for every recording.

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
    public class PullRecordingSessionExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: jrec_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new JrecApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | Recorded session ID

            try
            {
                // Downloads an entire recorded session as a ZIP archive
                FileParameter result = apiInstance.PullRecordingSession(id);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrecApi.PullRecordingSession: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PullRecordingSessionWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Downloads an entire recorded session as a ZIP archive
    ApiResponse<FileParameter> response = apiInstance.PullRecordingSessionWithHttpInfo(id);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrecApi.PullRecordingSessionWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** | Recorded session ID |  |

### Return type

[**FileParameter**](FileParameter.md)

### Authorization

[jrec_token](../README.md#jrec_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/zip


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | ZIP archive containing the recording session |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | Recording not found |  -  |
| **413** | Recording package exceeds download size or file-count limits |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="searchrecordings"></a>
# **SearchRecordings**
> RecordingSearchResponse SearchRecordings (RecordingSearchRequest recordingSearchRequest)

Searches the `.slog` artifacts, such as AI analysis logs, of recordings stored on this instance

The query is a case-insensitive substring, and an empty query matches every line. In a line holding a JSON object, it is matched against the string values of the object at any depth, as they read once unescaped, so field names, numbers, booleans and null never match. Any other line, such as one still being written, is matched as raw text. A line longer than 256 KiB is matched on its first 256 KiB only, by the same rule, so a cut JSON object is usually matched as raw text. Only the files listed under `artifacts` in `recording.json` with the `slog` type are searched. Recordings without a readable `recording.json` and IDs with no recording on this instance give no hits.  Results come in pages. To get the next page, send the same `query`, `recordings` and `startTime` again, with the `nextCursor` of the previous page as `cursor`. Pages never go back, so a recording that starts, or a log that grows, behind the cursor while paging is not searched.

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
    public class SearchRecordingsExample
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
            var apiInstance = new JrecApi(httpClient, config, httpClientHandler);
            var recordingSearchRequest = new RecordingSearchRequest(); // RecordingSearchRequest | JSON-encoded search request

            try
            {
                // Searches the `.slog` artifacts, such as AI analysis logs, of recordings stored on this instance
                RecordingSearchResponse result = apiInstance.SearchRecordings(recordingSearchRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrecApi.SearchRecordings: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the SearchRecordingsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Searches the `.slog` artifacts, such as AI analysis logs, of recordings stored on this instance
    ApiResponse<RecordingSearchResponse> response = apiInstance.SearchRecordingsWithHttpInfo(recordingSearchRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrecApi.SearchRecordingsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **recordingSearchRequest** | [**RecordingSearchRequest**](RecordingSearchRequest.md) | JSON-encoded search request |  |

### Return type

[**RecordingSearchResponse**](RecordingSearchResponse.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Matching log lines |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

