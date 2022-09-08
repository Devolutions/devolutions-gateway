# Devolutions.Gateway.Client.Api.JrlApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetJrlInfo**](JrlApi.md#getjrlinfo) | **GET** /jet/jrl/info | Retrieves current JRL (Json Revocation List) info |
| [**UpdateJrl**](JrlApi.md#updatejrl) | **POST** /jet/jrl | Updates JRL (Json Revocation List) using a JRL token |

<a name="getjrlinfo"></a>
# **GetJrlInfo**
> JrlInfo GetJrlInfo ()

Retrieves current JRL (Json Revocation List) info

Retrieves current JRL (Json Revocation List) info 

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class GetJrlInfoExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: scope_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new JrlApi(config);

            try
            {
                // Retrieves current JRL (Json Revocation List) info
                JrlInfo result = apiInstance.GetJrlInfo();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrlApi.GetJrlInfo: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetJrlInfoWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Retrieves current JRL (Json Revocation List) info
    ApiResponse<JrlInfo> response = apiInstance.GetJrlInfoWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrlApi.GetJrlInfoWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**JrlInfo**](JrlInfo.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Current JRL Info |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to update the JRL |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a name="updatejrl"></a>
# **UpdateJrl**
> void UpdateJrl ()

Updates JRL (Json Revocation List) using a JRL token

Updates JRL (Json Revocation List) using a JRL token 

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class UpdateJrlExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: jrl_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new JrlApi(config);

            try
            {
                // Updates JRL (Json Revocation List) using a JRL token
                apiInstance.UpdateJrl();
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling JrlApi.UpdateJrl: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the UpdateJrlWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Updates JRL (Json Revocation List) using a JRL token
    apiInstance.UpdateJrlWithHttpInfo();
}
catch (ApiException e)
{
    Debug.Print("Exception when calling JrlApi.UpdateJrlWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

void (empty response body)

### Authorization

[jrl_token](../README.md#jrl_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | JRL updated successfully |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Failed to update the JRL |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

