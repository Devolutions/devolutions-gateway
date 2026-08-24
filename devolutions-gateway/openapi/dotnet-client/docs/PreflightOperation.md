# Devolutions.Gateway.Client.Model.PreflightOperation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ConnectionOptions** | [**TargetConnectionOptions**](TargetConnectionOptions.md) |  | [optional] 
**HostToResolve** | **string** | The hostname to perform DNS resolution on.  Required for \&quot;resolve-host\&quot; kind. | [optional] 
**Id** | **Guid** | Unique ID identifying the preflight operation. | 
**Kind** | **PreflightOperationKind** |  | 
**ProxyCredential** | [**AppCredential**](AppCredential.md) |  | [optional] 
**TargetCredential** | [**AppCredential**](AppCredential.md) |  | [optional] 
**TimeToLive** | **int?** | Retention duration in seconds for data provisioned by this operation.  For \&quot;provision-credentials\&quot;, this is the maximum staging time before the first credential checkout. After checkout, Gateway retains the credentials for later connections authorized for the same association.  Optional parameter for \&quot;provision-token\&quot;, \&quot;provision-credentials\&quot;, and \&quot;provision-connection-options\&quot; kinds. | [optional] 
**Token** | **string** | The token to be stored on the proxy-side.  Required for \&quot;provision-token\&quot;, \&quot;provision-credentials\&quot;, and \&quot;provision-connection-options\&quot; kinds. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

