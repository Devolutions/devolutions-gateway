# Devolutions.Gateway.Client.Api.JrecApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**ListRecordings**](JrecApi.md#listrecordings) | **GET** /jet/jrec/list | Lists all recordings stored on this instance |
| [**PullRecordingFile**](JrecApi.md#pullrecordingfile) | **GET** /jet/jrec/pull/{id}/{filename} | Retrieves a recording file for a given session |

<a name="listrecordings"></a>
# **ListRecordings**
> List&lt;Guid&gt; ListRecordings ()

Lists all recordings stored on this instance

Lists all recordings stored on this instance

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
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

            var apiInstance = new JrecApi(config);

            try
            {
                // Lists all recordings stored on this instance
                List<Guid> result = apiInstance.ListRecordings();
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
    ApiResponse<List<Guid>> response = apiInstance.ListRecordingsWithHttpInfo();
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
This endpoint does not need any parameter.
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

<a name="pullrecordingfile"></a>
# **PullRecordingFile**
> System.IO.Stream PullRecordingFile (Guid id, string filename)

Retrieves a recording file for a given session

Retrieves a recording file for a given session

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
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
            var apiInstance = new JrecApi(config);
            var id = "id_example";  // Guid | Recorded session ID
            var filename = "filename_example";  // string | Name of recording file to retrieve

            try
            {
                // Retrieves a recording file for a given session
                System.IO.Stream result = apiInstance.PullRecordingFile(id, filename);
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
    ApiResponse<System.IO.Stream> response = apiInstance.PullRecordingFileWithHttpInfo(id, filename);
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

**System.IO.Stream**

### Authorization

No authorization required

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

