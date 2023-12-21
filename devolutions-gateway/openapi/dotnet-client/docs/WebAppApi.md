# Devolutions.Gateway.Client.Api.WebAppApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**SignAppToken**](WebAppApi.md#signapptoken) | **POST** /jet/webapp/app-token | Requests a web application token using the configured authorization method |
| [**SignSessionToken**](WebAppApi.md#signsessiontoken) | **POST** /jet/webapp/session-token | Requests a session token using a web application token |

<a name="signapptoken"></a>
# **SignAppToken**
> string SignAppToken (AppTokenSignRequest appTokenSignRequest)

Requests a web application token using the configured authorization method

Requests a web application token using the configured authorization method

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class SignAppTokenExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure HTTP basic authorization: web_app_custom_auth
            config.Username = "YOUR_USERNAME";
            config.Password = "YOUR_PASSWORD";

            var apiInstance = new WebAppApi(config);
            var appTokenSignRequest = new AppTokenSignRequest(); // AppTokenSignRequest | JSON-encoded payload specifying the desired claims

            try
            {
                // Requests a web application token using the configured authorization method
                string result = apiInstance.SignAppToken(appTokenSignRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling WebAppApi.SignAppToken: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the SignAppTokenWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Requests a web application token using the configured authorization method
    ApiResponse<string> response = apiInstance.SignAppTokenWithHttpInfo(appTokenSignRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling WebAppApi.SignAppTokenWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **appTokenSignRequest** | [**AppTokenSignRequest**](AppTokenSignRequest.md) | JSON-encoded payload specifying the desired claims |  |

### Return type

**string**

### Authorization

[web_app_custom_auth](../README.md#web_app_custom_auth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: text/plain


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The application token has been granted |  -  |
| **400** | Bad signature request |  -  |
| **401** | Invalid or missing authorization header |  -  |
| **403** | Insufficient permissions |  -  |
| **415** | Unsupported content type in request body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a name="signsessiontoken"></a>
# **SignSessionToken**
> string SignSessionToken (SessionTokenSignRequest sessionTokenSignRequest)

Requests a session token using a web application token

Requests a session token using a web application token

### Example
```csharp
using System.Collections.Generic;
using System.Diagnostics;
using Devolutions.Gateway.Client.Api;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Example
{
    public class SignSessionTokenExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: web_app_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            var apiInstance = new WebAppApi(config);
            var sessionTokenSignRequest = new SessionTokenSignRequest(); // SessionTokenSignRequest | JSON-encoded payload specifying the desired claims

            try
            {
                // Requests a session token using a web application token
                string result = apiInstance.SignSessionToken(sessionTokenSignRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling WebAppApi.SignSessionToken: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the SignSessionTokenWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Requests a session token using a web application token
    ApiResponse<string> response = apiInstance.SignSessionTokenWithHttpInfo(sessionTokenSignRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling WebAppApi.SignSessionTokenWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **sessionTokenSignRequest** | [**SessionTokenSignRequest**](SessionTokenSignRequest.md) | JSON-encoded payload specifying the desired claims |  |

### Return type

**string**

### Authorization

[web_app_token](../README.md#web_app_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: text/plain


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | The application token has been granted |  -  |
| **400** | Bad signature request |  -  |
| **401** | Invalid or missing authorization header |  -  |
| **403** | Insufficient permissions |  -  |
| **415** | Unsupported content type in request body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

