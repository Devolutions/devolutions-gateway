# Devolutions.Gateway.Client.Api.AgentApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**DeleteAgent**](AgentApi.md#deleteagent) | **DELETE** /jet/tunnel/agents/{agent_id} | Delete an accepted agent by ID. |
| [**EnrollAgent**](AgentApi.md#enrollagent) | **POST** /jet/tunnel/enroll | Enroll a new agent. |
| [**GetAgent**](AgentApi.md#getagent) | **GET** /jet/tunnel/agents/{agent_id} | Get a single agent by ID. |
| [**ListAgents**](AgentApi.md#listagents) | **GET** /jet/tunnel/agents | List accepted agents and their current status. |

<a id="deleteagent"></a>
# **DeleteAgent**
> void DeleteAgent (Guid agentId)

Delete an accepted agent by ID.

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
    public class DeleteAgentExample
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
            var apiInstance = new AgentApi(httpClient, config, httpClientHandler);
            var agentId = "agentId_example";  // Guid | Agent ID

            try
            {
                // Delete an accepted agent by ID.
                apiInstance.DeleteAgent(agentId);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling AgentApi.DeleteAgent: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the DeleteAgentWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Delete an accepted agent by ID.
    apiInstance.DeleteAgentWithHttpInfo(agentId);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling AgentApi.DeleteAgentWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **agentId** | **Guid** | Agent ID |  |

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
| **204** | Agent deleted |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | Agent not found |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="enrollagent"></a>
# **EnrollAgent**
> EnrollResponse EnrollAgent (EnrollRequest enrollRequest)

Enroll a new agent.

Requires a Bearer token: an `ENROLLMENT` JWT signed by the configured provisioner key (e.g. DVLS, Hub, PAM service, or any other compatible provisioner).  The agent generates its own key pair and sends a CSR. The gateway signs it and returns the certificate. The private key never leaves the agent.

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
    public class EnrollAgentExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: enrollment_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new AgentApi(httpClient, config, httpClientHandler);
            var enrollRequest = new EnrollRequest(); // EnrollRequest | Agent identity and certificate signing request

            try
            {
                // Enroll a new agent.
                EnrollResponse result = apiInstance.EnrollAgent(enrollRequest);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling AgentApi.EnrollAgent: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the EnrollAgentWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Enroll a new agent.
    ApiResponse<EnrollResponse> response = apiInstance.EnrollAgentWithHttpInfo(enrollRequest);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling AgentApi.EnrollAgentWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **enrollRequest** | [**EnrollRequest**](EnrollRequest.md) | Agent identity and certificate signing request |  |

### Return type

[**EnrollResponse**](EnrollResponse.md)

### Authorization

[enrollment_token](../README.md#enrollment_token)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Agent enrolled |  -  |
| **400** | Invalid agent name, request body, or certificate signing request |  -  |
| **401** | Invalid or missing enrollment token |  -  |
| **409** | Agent ID already registered |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="getagent"></a>
# **GetAgent**
> AgentInfo GetAgent (Guid agentId)

Get a single agent by ID.

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
    public class GetAgentExample
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
            var apiInstance = new AgentApi(httpClient, config, httpClientHandler);
            var agentId = "agentId_example";  // Guid | Agent ID

            try
            {
                // Get a single agent by ID.
                AgentInfo result = apiInstance.GetAgent(agentId);
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling AgentApi.GetAgent: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetAgentWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Get a single agent by ID.
    ApiResponse<AgentInfo> response = apiInstance.GetAgentWithHttpInfo(agentId);
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling AgentApi.GetAgentWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **agentId** | **Guid** | Agent ID |  |

### Return type

[**AgentInfo**](AgentInfo.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Agent status |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **404** | Agent not found |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="listagents"></a>
# **ListAgents**
> List&lt;AgentInfo&gt; ListAgents ()

List accepted agents and their current status.

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
    public class ListAgentsExample
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
            var apiInstance = new AgentApi(httpClient, config, httpClientHandler);

            try
            {
                // List accepted agents and their current status.
                List<AgentInfo> result = apiInstance.ListAgents();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling AgentApi.ListAgents: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the ListAgentsWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // List accepted agents and their current status.
    ApiResponse<List<AgentInfo>> response = apiInstance.ListAgentsWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling AgentApi.ListAgentsWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**List&lt;AgentInfo&gt;**](AgentInfo.md)

### Authorization

[scope_token](../README.md#scope_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Accepted agents and their current status |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

