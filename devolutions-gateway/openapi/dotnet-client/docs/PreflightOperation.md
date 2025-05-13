# Devolutions.Gateway.Client.Model.PreflightOperation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**HostToResolve** | **string** | The hostname to perform DNS resolution on.  Required for \&quot;resolve-host\&quot; kind. | [optional] 
**Id** | **Guid** | Unique ID identifying the preflight operation. | 
**Kind** | **PreflightOperationKind** |  | 
**ProxyCredential** | [**AppCredential**](AppCredential.md) |  | [optional] 
**TargetCredential** | [**AppCredential**](AppCredential.md) |  | [optional] 
**TimeToLive** | **int?** | Minimum persistance duration in seconds for the data provisioned via this operation.  Optional parameter for \&quot;provision-token\&quot; and \&quot;provision-credentials\&quot; kinds. | [optional] 
**Token** | **string** | The token to be stored on the proxy-side.  Required for \&quot;provision-token\&quot; and \&quot;provision-credentials\&quot; kind. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

