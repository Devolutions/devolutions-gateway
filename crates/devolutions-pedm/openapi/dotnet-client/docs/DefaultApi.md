# Devolutions.Pedm.Client.Api.DefaultApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**AboutGet**](DefaultApi.md#aboutget) | **GET** /about |  |
| [**ElevateSessionPost**](DefaultApi.md#elevatesessionpost) | **POST** /elevate/session |  |
| [**ElevateTemporaryPost**](DefaultApi.md#elevatetemporarypost) | **POST** /elevate/temporary |  |
| [**LaunchPost**](DefaultApi.md#launchpost) | **POST** /launch |  |
| [**LogJitGet**](DefaultApi.md#logjitget) | **GET** /log/jit |  |
| [**PolicyAssignmentsGet**](DefaultApi.md#policyassignmentsget) | **GET** /policy/assignments |  |
| [**PolicyAssignmentsIdPut**](DefaultApi.md#policyassignmentsidput) | **PUT** /policy/assignments/{id} |  |
| [**PolicyMeGet**](DefaultApi.md#policymeget) | **GET** /policy/me |  |
| [**PolicyMePut**](DefaultApi.md#policymeput) | **PUT** /policy/me |  |
| [**PolicyProfilesGet**](DefaultApi.md#policyprofilesget) | **GET** /policy/profiles |  |
| [**PolicyProfilesIdDelete**](DefaultApi.md#policyprofilesiddelete) | **DELETE** /policy/profiles/{id} |  |
| [**PolicyProfilesIdGet**](DefaultApi.md#policyprofilesidget) | **GET** /policy/profiles/{id} |  |
| [**PolicyProfilesIdPut**](DefaultApi.md#policyprofilesidput) | **PUT** /policy/profiles/{id} |  |
| [**PolicyProfilesPost**](DefaultApi.md#policyprofilespost) | **POST** /policy/profiles |  |
| [**RevokePost**](DefaultApi.md#revokepost) | **POST** /revoke |  |
| [**StatusGet**](DefaultApi.md#statusget) | **GET** /status |  |

<a id="aboutget"></a>
# **AboutGet**
> AboutData AboutGet ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class AboutGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                AboutData result = apiInstance.AboutGet();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.AboutGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the AboutGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<AboutData> response = apiInstance.AboutGetWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.AboutGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**AboutData**](AboutData.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="elevatesessionpost"></a>
# **ElevateSessionPost**
> void ElevateSessionPost ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class ElevateSessionPostExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                apiInstance.ElevateSessionPost();
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.ElevateSessionPost: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the ElevateSessionPostWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.ElevateSessionPostWithHttpInfo();
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.ElevateSessionPostWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="elevatetemporarypost"></a>
# **ElevateTemporaryPost**
> void ElevateTemporaryPost (ElevateTemporaryPayload elevateTemporaryPayload)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class ElevateTemporaryPostExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var elevateTemporaryPayload = new ElevateTemporaryPayload(); // ElevateTemporaryPayload | 

            try
            {
                apiInstance.ElevateTemporaryPost(elevateTemporaryPayload);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.ElevateTemporaryPost: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the ElevateTemporaryPostWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.ElevateTemporaryPostWithHttpInfo(elevateTemporaryPayload);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.ElevateTemporaryPostWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **elevateTemporaryPayload** | [**ElevateTemporaryPayload**](ElevateTemporaryPayload.md) |  |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="launchpost"></a>
# **LaunchPost**
> LaunchResponse LaunchPost (LaunchPayload launchPayload)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class LaunchPostExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var launchPayload = new LaunchPayload(); // LaunchPayload | 

            try
            {
                LaunchResponse result = apiInstance.LaunchPost(launchPayload);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.LaunchPost: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the LaunchPostWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<LaunchResponse> response = apiInstance.LaunchPostWithHttpInfo(launchPayload);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.LaunchPostWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **launchPayload** | [**LaunchPayload**](LaunchPayload.md) |  |  |

### Return type

[**LaunchResponse**](LaunchResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="logjitget"></a>
# **LogJitGet**
> JitElevationLogPage LogJitGet (JitElevationLogQueryOptions jitElevationLogQueryOptions)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class LogJitGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var jitElevationLogQueryOptions = new JitElevationLogQueryOptions(); // JitElevationLogQueryOptions | 

            try
            {
                JitElevationLogPage result = apiInstance.LogJitGet(jitElevationLogQueryOptions);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.LogJitGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the LogJitGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<JitElevationLogPage> response = apiInstance.LogJitGetWithHttpInfo(jitElevationLogQueryOptions);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.LogJitGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **jitElevationLogQueryOptions** | [**JitElevationLogQueryOptions**](JitElevationLogQueryOptions.md) |  |  |

### Return type

[**JitElevationLogPage**](JitElevationLogPage.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyassignmentsget"></a>
# **PolicyAssignmentsGet**
> List&lt;Assignment&gt; PolicyAssignmentsGet ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyAssignmentsGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                List<Assignment> result = apiInstance.PolicyAssignmentsGet();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyAssignmentsGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyAssignmentsGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<List<Assignment>> response = apiInstance.PolicyAssignmentsGetWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyAssignmentsGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**List&lt;Assignment&gt;**](Assignment.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyassignmentsidput"></a>
# **PolicyAssignmentsIdPut**
> void PolicyAssignmentsIdPut (Guid id, List<User> user)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyAssignmentsIdPutExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | 
            var user = new List<User>(); // List<User> | 

            try
            {
                apiInstance.PolicyAssignmentsIdPut(id, user);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyAssignmentsIdPut: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyAssignmentsIdPutWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.PolicyAssignmentsIdPutWithHttpInfo(id, user);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyAssignmentsIdPutWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** |  |  |
| **user** | [**List&lt;User&gt;**](User.md) |  |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policymeget"></a>
# **PolicyMeGet**
> GetProfilesMeResponse PolicyMeGet ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyMeGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                GetProfilesMeResponse result = apiInstance.PolicyMeGet();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyMeGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyMeGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<GetProfilesMeResponse> response = apiInstance.PolicyMeGetWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyMeGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**GetProfilesMeResponse**](GetProfilesMeResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Returns some information about the current user and active profiles.  If there is no active profile, the &#x60;active&#x60; UUID will be full of zeroes. |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policymeput"></a>
# **PolicyMePut**
> void PolicyMePut (OptionalId optionalId)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyMePutExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var optionalId = new OptionalId(); // OptionalId | 

            try
            {
                apiInstance.PolicyMePut(optionalId);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyMePut: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyMePutWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.PolicyMePutWithHttpInfo(optionalId);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyMePutWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **optionalId** | [**OptionalId**](OptionalId.md) |  |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyprofilesget"></a>
# **PolicyProfilesGet**
> List&lt;Guid&gt; PolicyProfilesGet ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyProfilesGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                List<Guid> result = apiInstance.PolicyProfilesGet();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyProfilesGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyProfilesGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<List<Guid>> response = apiInstance.PolicyProfilesGetWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyProfilesGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

**List<Guid>**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyprofilesiddelete"></a>
# **PolicyProfilesIdDelete**
> void PolicyProfilesIdDelete (Guid id)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyProfilesIdDeleteExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | 

            try
            {
                apiInstance.PolicyProfilesIdDelete(id);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyProfilesIdDelete: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyProfilesIdDeleteWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.PolicyProfilesIdDeleteWithHttpInfo(id);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyProfilesIdDeleteWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** |  |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyprofilesidget"></a>
# **PolicyProfilesIdGet**
> Profile PolicyProfilesIdGet (Guid id)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyProfilesIdGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | 

            try
            {
                Profile result = apiInstance.PolicyProfilesIdGet(id);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyProfilesIdGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyProfilesIdGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<Profile> response = apiInstance.PolicyProfilesIdGetWithHttpInfo(id);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyProfilesIdGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** |  |  |

### Return type

[**Profile**](Profile.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyprofilesidput"></a>
# **PolicyProfilesIdPut**
> void PolicyProfilesIdPut (Guid id, Profile profile)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyProfilesIdPutExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var id = "id_example";  // Guid | 
            var profile = new Profile(); // Profile | 

            try
            {
                apiInstance.PolicyProfilesIdPut(id, profile);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyProfilesIdPut: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyProfilesIdPutWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.PolicyProfilesIdPutWithHttpInfo(id, profile);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyProfilesIdPutWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **id** | **Guid** |  |  |
| **profile** | [**Profile**](Profile.md) |  |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="policyprofilespost"></a>
# **PolicyProfilesPost**
> void PolicyProfilesPost (Profile profile)



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class PolicyProfilesPostExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);
            var profile = new Profile(); // Profile | 

            try
            {
                apiInstance.PolicyProfilesPost(profile);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.PolicyProfilesPost: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the PolicyProfilesPostWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.PolicyProfilesPostWithHttpInfo(profile);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.PolicyProfilesPostWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **profile** | [**Profile**](Profile.md) |  |  |

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="revokepost"></a>
# **RevokePost**
> void RevokePost ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class RevokePostExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                apiInstance.RevokePost();
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.RevokePost: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the RevokePostWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    apiInstance.RevokePostWithHttpInfo();
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.RevokePostWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | no content |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="statusget"></a>
# **StatusGet**
> StatusResponse StatusGet ()



### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Client;
using Devolutions.Pedm.Client.Model;

namespace Example
{
    public class StatusGetExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new DefaultApi(httpClient, config, httpClientHandler);

            try
            {
                StatusResponse result = apiInstance.StatusGet();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling DefaultApi.StatusGet: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the StatusGetWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    ApiResponse<StatusResponse> response = apiInstance.StatusGetWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling DefaultApi.StatusGetWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**StatusResponse**](StatusResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** |  |  -  |
| **0** |  |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

