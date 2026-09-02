# Devolutions.Gateway.Client.Model.AgentInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AgentId** | **Guid** | Stable Agent identity. | 
**Domains** | [**List&lt;AgentDomainAdvertisement&gt;**](AgentDomainAdvertisement.md) | Domain routes currently advertised by the Agent. | [optional] 
**LastSeenMs** | **long?** | Last heartbeat timestamp in milliseconds since the Unix epoch. | [optional] 
**Name** | **string** | Unique management name assigned during enrollment. | 
**Status** | **AgentStatus** |  | 
**Subnets** | **List&lt;string&gt;** | Subnet routes currently advertised by the Agent. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

