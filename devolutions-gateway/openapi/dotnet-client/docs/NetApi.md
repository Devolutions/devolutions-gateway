# Devolutions.Gateway.Client.Api.NetApi

All URIs are relative to *http://localhost*

| Method | HTTP request | Description |
|--------|--------------|-------------|
| [**GetNetConfig**](NetApi.md#getnetconfig) | **GET** /jet/net/config | Lists network interfaces |
| [**GetNetInterfaces**](NetApi.md#getnetinterfaces) | **GET** /jet/net/interfaces | Lists Gateway network scan sources. |
| [**GetNetScan**](NetApi.md#getnetscan) | **GET** /jet/net/scan | Stream network scan events over a websocket. |

<a id="getnetconfig"></a>
# **GetNetConfig**
> List&lt;Dictionary&lt;string, List&lt;InterfaceInfo&gt;&gt;&gt; GetNetConfig ()

Lists network interfaces

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
    public class GetNetConfigExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: netscan_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new NetApi(httpClient, config, httpClientHandler);

            try
            {
                // Lists network interfaces
                List<Dictionary<string, List<InterfaceInfo>>> result = apiInstance.GetNetConfig();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling NetApi.GetNetConfig: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetNetConfigWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Lists network interfaces
    ApiResponse<List<Dictionary<string, List<InterfaceInfo>>>> response = apiInstance.GetNetConfigWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling NetApi.GetNetConfigWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

**List<Dictionary<string, List<InterfaceInfo>>>**

### Authorization

[netscan_token](../README.md#netscan_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Network interfaces |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="getnetinterfaces"></a>
# **GetNetInterfaces**
> NetworkInterfacesResponse GetNetInterfaces ()

Lists Gateway network scan sources.

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
    public class GetNetInterfacesExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: netscan_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new NetApi(httpClient, config, httpClientHandler);

            try
            {
                // Lists Gateway network scan sources.
                NetworkInterfacesResponse result = apiInstance.GetNetInterfaces();
                Debug.WriteLine(result);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling NetApi.GetNetInterfaces: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetNetInterfacesWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Lists Gateway network scan sources.
    ApiResponse<NetworkInterfacesResponse> response = apiInstance.GetNetInterfacesWithHttpInfo();
    Debug.Write("Status Code: " + response.StatusCode);
    Debug.Write("Response Headers: " + response.Headers);
    Debug.Write("Response Body: " + response.Data);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling NetApi.GetNetInterfacesWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters
This endpoint does not need any parameter.
### Return type

[**NetworkInterfacesResponse**](NetworkInterfacesResponse.md)

### Authorization

[netscan_token](../README.md#netscan_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Gateway network scan sources |  -  |
| **400** | Bad request |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

<a id="getnetscan"></a>
# **GetNetScan**
> void GetNetScan (long? pingInterval = null, long? pingTimeout = null, long? broadcastTimeout = null, long? portScanTimeout = null, long? netbiosTimeout = null, long? netbiosInterval = null, long? mdnsQueryTimeout = null, long? maxWait = null, List<string>? range = null, List<string>? target = null, List<string>? interfaceId = null, List<string>? probe = null, bool? enablePingStart = null, bool? enableBroadcast = null, bool? enableSubnetScan = null, bool? enableZeroconf = null, bool? enableNetbios = null, bool? enableResolveDns = null, bool? includeHostResults = null, bool? reportPingStart = null, bool? reportPingSuccess = null, bool? reportPingFailure = null, bool? enableTcpProbes = null, string? rangeInterfacePolicy = null, bool? allowCrossInterfaceRange = null, string? responseFormat = null, int? maxConcurrency = null, int? maxPingConcurrency = null, int? maxTcpProbeConcurrency = null, bool? enableFailure = null, bool? reportTcpFailure = null, bool? interfaceBindStrict = null)

Stream network scan events over a websocket.

The endpoint is upgraded from HTTP, so OpenAPI describes the **handshake**: the query parameters that drive the scan (validated before upgrade) and the legacy / v1 event payloads streamed back as JSON text frames. See `NetworkScanResultEvent` for the v1 shape and `LegacyScanEvent` for the legacy shape (selected via `response_format`).

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
    public class GetNetScanExample
    {
        public static void Main()
        {
            Configuration config = new Configuration();
            config.BasePath = "http://localhost";
            // Configure Bearer token for authorization: netscan_token
            config.AccessToken = "YOUR_BEARER_TOKEN";

            // create instances of HttpClient, HttpClientHandler to be reused later with different Api classes
            HttpClient httpClient = new HttpClient();
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            var apiInstance = new NetApi(httpClient, config, httpClientHandler);
            var pingInterval = 789L;  // long? | Interval in milliseconds (default is 200) (optional) 
            var pingTimeout = 789L;  // long? | Timeout in milliseconds (default is 500) (optional) 
            var broadcastTimeout = 789L;  // long? | Timeout in milliseconds (default is 1000) (optional) 
            var portScanTimeout = 789L;  // long? | Timeout in milliseconds (default is 1000) (optional) 
            var netbiosTimeout = 789L;  // long? | Timeout in milliseconds (default is 1000) (optional) 
            var netbiosInterval = 789L;  // long? | Interval in milliseconds (default is 200) (optional) 
            var mdnsQueryTimeout = 789L;  // long? | The maximum time for each mdns query in milliseconds. (default is 5 * 1000) (optional) 
            var maxWait = 789L;  // long? | The maximum duration for whole networking scan in milliseconds. Highly suggested! (optional) 
            var range = new List<string>?(); // List<string>? | The start and end IP address of the range to scan. for example: 10.10.0.0-10.10.0.255 (optional) 
            var target = new List<string>?(); // List<string>? | Explicit single-host targets to scan. Each value must parse as an IPv4 or IPv6 address; invalid values yield a structured `{ error: \"invalid_target\", value: \"<raw>\" }` 400 rather than a generic serde rejection at extraction time (mirrors the `range=` / `probe=` validation path). (optional) 
            var interfaceId = new List<string>?(); // List<string>? | Gateway network interface IDs to use as scan sources. (optional) 
            var probe = new List<string>?(); // List<string>? | The probes to run. Each value is either `ping`, a port number (`22`), or a named service (`rdp`, `https`, …). Validation is deferred to scan-time so failures can be surfaced as a structured 400 — naming the offending value — instead of a generic serde rejection at extraction time. (optional) 
            var enablePingStart = true;  // bool? | **Legacy alias** for `report_ping_start`. Prefer the explicit name in new clients; kept so existing consumers don't break. (optional) 
            var enableBroadcast = true;  // bool? | Enable the execution of broadcast scan (optional) 
            var enableSubnetScan = true;  // bool? | Enable the ping scan on subnet (optional) 
            var enableZeroconf = true;  // bool? | Enable ZeroConf/mDNS (optional) 
            var enableNetbios = true;  // bool? | Enable NetBIOS name-service queries. Default `true` for backward compatibility. Set `false` (or pair with explicit `target=`) to keep NetBIOS from sweeping the surrounding subnet when the caller only wants results for the targets they listed. (optional) 
            var enableResolveDns = true;  // bool? | Enable resolve dns (optional) 
            var includeHostResults = true;  // bool? | Include host-only results. (optional) 
            var reportPingStart = true;  // bool? | Emit ping queued/start host results. (optional) 
            var reportPingSuccess = true;  // bool? | Emit ping success host results. (optional) 
            var reportPingFailure = true;  // bool? | Emit ping failure host results. (optional) 
            var enableTcpProbes = true;  // bool? | Enable TCP service probes. (optional) 
            var rangeInterfacePolicy = "rangeInterfacePolicy_example";  // string? | Policy applied when `range=` and `interface_id=` are both provided. Accepted values: `intersect_selected_interfaces` (default) or `allow_cross_interface_range`. Invalid values yield a structured `{ error: \"invalid_range_interface_policy\", value: \"<raw>\" }` 400 instead of a generic serde rejection (mirrors the `range=` / `probe=` / `target=` validation path). (optional) 
            var allowCrossInterfaceRange = true;  // bool? | **Legacy alias** for `range_interface_policy=allow_cross_interface_range`. Prefer the structured policy in new clients. (optional) 
            var responseFormat = "responseFormat_example";  // string? | Response shape emitted on the websocket. Accepted values: `legacy` (default) or `network_scan_result_v1`. Invalid values yield a structured `{ error: \"invalid_response_format\", value: \"<raw>\" }` 400 instead of a generic serde rejection. (optional) 
            var maxConcurrency = 56;  // int? | Maximum scanner concurrency. (optional) 
            var maxPingConcurrency = 56;  // int? | Maximum ping probe concurrency. (optional) 
            var maxTcpProbeConcurrency = 56;  // int? | Maximum TCP probe concurrency. (optional) 
            var enableFailure = true;  // bool? | **Legacy alias** for `report_ping_failure`. `enable_failure=true` only opts into ping-failure events; TCP-probe failure events require the explicit `report_tcp_failure=true` and are not affected by this alias.  **Behavior change:** historically this single flag controlled both ping-failure and TCP-probe-failure reporting. The two are now split: clients that want the old \"both at once\" semantics must send `enable_failure=true&report_tcp_failure=true` together. The split is intentional — TCP-probe failures are typically high-volume noise that callers were filtering client-side anyway, so the two streams are independently gated. (optional) 
            var reportTcpFailure = true;  // bool? | Enable TCP port knocking failure events. (optional) 
            var interfaceBindStrict = true;  // bool? | When `true`, fail with HTTP 400 if a ping/TCP-probe socket cannot be bound to the planner-selected interface. Default `false` (warn and fall back to default routing). (optional) 

            try
            {
                // Stream network scan events over a websocket.
                apiInstance.GetNetScan(pingInterval, pingTimeout, broadcastTimeout, portScanTimeout, netbiosTimeout, netbiosInterval, mdnsQueryTimeout, maxWait, range, target, interfaceId, probe, enablePingStart, enableBroadcast, enableSubnetScan, enableZeroconf, enableNetbios, enableResolveDns, includeHostResults, reportPingStart, reportPingSuccess, reportPingFailure, enableTcpProbes, rangeInterfacePolicy, allowCrossInterfaceRange, responseFormat, maxConcurrency, maxPingConcurrency, maxTcpProbeConcurrency, enableFailure, reportTcpFailure, interfaceBindStrict);
            }
            catch (ApiException  e)
            {
                Debug.Print("Exception when calling NetApi.GetNetScan: " + e.Message);
                Debug.Print("Status Code: " + e.ErrorCode);
                Debug.Print(e.StackTrace);
            }
        }
    }
}
```

#### Using the GetNetScanWithHttpInfo variant
This returns an ApiResponse object which contains the response data, status code and headers.

```csharp
try
{
    // Stream network scan events over a websocket.
    apiInstance.GetNetScanWithHttpInfo(pingInterval, pingTimeout, broadcastTimeout, portScanTimeout, netbiosTimeout, netbiosInterval, mdnsQueryTimeout, maxWait, range, target, interfaceId, probe, enablePingStart, enableBroadcast, enableSubnetScan, enableZeroconf, enableNetbios, enableResolveDns, includeHostResults, reportPingStart, reportPingSuccess, reportPingFailure, enableTcpProbes, rangeInterfacePolicy, allowCrossInterfaceRange, responseFormat, maxConcurrency, maxPingConcurrency, maxTcpProbeConcurrency, enableFailure, reportTcpFailure, interfaceBindStrict);
}
catch (ApiException e)
{
    Debug.Print("Exception when calling NetApi.GetNetScanWithHttpInfo: " + e.Message);
    Debug.Print("Status Code: " + e.ErrorCode);
    Debug.Print(e.StackTrace);
}
```

### Parameters

| Name | Type | Description | Notes |
|------|------|-------------|-------|
| **pingInterval** | **long?** | Interval in milliseconds (default is 200) | [optional]  |
| **pingTimeout** | **long?** | Timeout in milliseconds (default is 500) | [optional]  |
| **broadcastTimeout** | **long?** | Timeout in milliseconds (default is 1000) | [optional]  |
| **portScanTimeout** | **long?** | Timeout in milliseconds (default is 1000) | [optional]  |
| **netbiosTimeout** | **long?** | Timeout in milliseconds (default is 1000) | [optional]  |
| **netbiosInterval** | **long?** | Interval in milliseconds (default is 200) | [optional]  |
| **mdnsQueryTimeout** | **long?** | The maximum time for each mdns query in milliseconds. (default is 5 * 1000) | [optional]  |
| **maxWait** | **long?** | The maximum duration for whole networking scan in milliseconds. Highly suggested! | [optional]  |
| **range** | [**List&lt;string&gt;?**](string.md) | The start and end IP address of the range to scan. for example: 10.10.0.0-10.10.0.255 | [optional]  |
| **target** | [**List&lt;string&gt;?**](string.md) | Explicit single-host targets to scan. Each value must parse as an IPv4 or IPv6 address; invalid values yield a structured &#x60;{ error: \&quot;invalid_target\&quot;, value: \&quot;&lt;raw&gt;\&quot; }&#x60; 400 rather than a generic serde rejection at extraction time (mirrors the &#x60;range&#x3D;&#x60; / &#x60;probe&#x3D;&#x60; validation path). | [optional]  |
| **interfaceId** | [**List&lt;string&gt;?**](string.md) | Gateway network interface IDs to use as scan sources. | [optional]  |
| **probe** | [**List&lt;string&gt;?**](string.md) | The probes to run. Each value is either &#x60;ping&#x60;, a port number (&#x60;22&#x60;), or a named service (&#x60;rdp&#x60;, &#x60;https&#x60;, …). Validation is deferred to scan-time so failures can be surfaced as a structured 400 — naming the offending value — instead of a generic serde rejection at extraction time. | [optional]  |
| **enablePingStart** | **bool?** | **Legacy alias** for &#x60;report_ping_start&#x60;. Prefer the explicit name in new clients; kept so existing consumers don&#39;t break. | [optional]  |
| **enableBroadcast** | **bool?** | Enable the execution of broadcast scan | [optional]  |
| **enableSubnetScan** | **bool?** | Enable the ping scan on subnet | [optional]  |
| **enableZeroconf** | **bool?** | Enable ZeroConf/mDNS | [optional]  |
| **enableNetbios** | **bool?** | Enable NetBIOS name-service queries. Default &#x60;true&#x60; for backward compatibility. Set &#x60;false&#x60; (or pair with explicit &#x60;target&#x3D;&#x60;) to keep NetBIOS from sweeping the surrounding subnet when the caller only wants results for the targets they listed. | [optional]  |
| **enableResolveDns** | **bool?** | Enable resolve dns | [optional]  |
| **includeHostResults** | **bool?** | Include host-only results. | [optional]  |
| **reportPingStart** | **bool?** | Emit ping queued/start host results. | [optional]  |
| **reportPingSuccess** | **bool?** | Emit ping success host results. | [optional]  |
| **reportPingFailure** | **bool?** | Emit ping failure host results. | [optional]  |
| **enableTcpProbes** | **bool?** | Enable TCP service probes. | [optional]  |
| **rangeInterfacePolicy** | **string?** | Policy applied when &#x60;range&#x3D;&#x60; and &#x60;interface_id&#x3D;&#x60; are both provided. Accepted values: &#x60;intersect_selected_interfaces&#x60; (default) or &#x60;allow_cross_interface_range&#x60;. Invalid values yield a structured &#x60;{ error: \&quot;invalid_range_interface_policy\&quot;, value: \&quot;&lt;raw&gt;\&quot; }&#x60; 400 instead of a generic serde rejection (mirrors the &#x60;range&#x3D;&#x60; / &#x60;probe&#x3D;&#x60; / &#x60;target&#x3D;&#x60; validation path). | [optional]  |
| **allowCrossInterfaceRange** | **bool?** | **Legacy alias** for &#x60;range_interface_policy&#x3D;allow_cross_interface_range&#x60;. Prefer the structured policy in new clients. | [optional]  |
| **responseFormat** | **string?** | Response shape emitted on the websocket. Accepted values: &#x60;legacy&#x60; (default) or &#x60;network_scan_result_v1&#x60;. Invalid values yield a structured &#x60;{ error: \&quot;invalid_response_format\&quot;, value: \&quot;&lt;raw&gt;\&quot; }&#x60; 400 instead of a generic serde rejection. | [optional]  |
| **maxConcurrency** | **int?** | Maximum scanner concurrency. | [optional]  |
| **maxPingConcurrency** | **int?** | Maximum ping probe concurrency. | [optional]  |
| **maxTcpProbeConcurrency** | **int?** | Maximum TCP probe concurrency. | [optional]  |
| **enableFailure** | **bool?** | **Legacy alias** for &#x60;report_ping_failure&#x60;. &#x60;enable_failure&#x3D;true&#x60; only opts into ping-failure events; TCP-probe failure events require the explicit &#x60;report_tcp_failure&#x3D;true&#x60; and are not affected by this alias.  **Behavior change:** historically this single flag controlled both ping-failure and TCP-probe-failure reporting. The two are now split: clients that want the old \&quot;both at once\&quot; semantics must send &#x60;enable_failure&#x3D;true&amp;report_tcp_failure&#x3D;true&#x60; together. The split is intentional — TCP-probe failures are typically high-volume noise that callers were filtering client-side anyway, so the two streams are independently gated. | [optional]  |
| **reportTcpFailure** | **bool?** | Enable TCP port knocking failure events. | [optional]  |
| **interfaceBindStrict** | **bool?** | When &#x60;true&#x60;, fail with HTTP 400 if a ping/TCP-probe socket cannot be bound to the planner-selected interface. Default &#x60;false&#x60; (warn and fall back to default routing). | [optional]  |

### Return type

void (empty response body)

### Authorization

[netscan_token](../README.md#netscan_token)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **101** | WebSocket upgrade; subsequent text frames carry NetworkScanResultEvent or LegacyScanEvent JSON |  -  |
| **400** | Invalid query, mixed target/range, oversized range, or selected interface error |  -  |
| **401** | Invalid or missing authorization token |  -  |
| **403** | Insufficient permissions |  -  |
| **500** | Unexpected server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

