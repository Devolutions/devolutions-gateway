# Devolutions.Gateway.Client.Model.PreflightOperation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AssociationId** | **Guid?** | A unique ID identifying the session for which the credentials should be used.  Required for \&quot;push-credentials\&quot; kind. | [optional] 
**HostToLookup** | **string** | The hostname to perform DNS lookup on.  Required for \&quot;lookup-host\&quot; kind. | [optional] 
**Id** | **Guid** | Unique ID identifying the preflight operation. | 
**Kind** | **PreflightOperationKind** |  | 
**ProxyCredentials** | [**Credentials**](Credentials.md) |  | [optional] 
**TargetCredentials** | [**Credentials**](Credentials.md) |  | [optional] 
**Token** | **string** | The token to be pushed on the proxy-side.  Required for \&quot;push-token\&quot; kind. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

