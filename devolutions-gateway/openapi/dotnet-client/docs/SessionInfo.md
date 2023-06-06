# Devolutions.Gateway.Client.Model.SessionInfo
Information about an ongoing Gateway session

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ApplicationProtocol** | **string** | Protocol used during this session | 
**AssociationId** | **Guid** | Unique ID for this session | 
**ConnectionMode** | **ConnectionMode** |  | 
**DestinationHost** | **string** | Destination Host | [optional] 
**FilteringPolicy** | **bool** | Filtering Policy | 
**RecordingPolicy** | **bool** | Recording Policy | 
**StartTimestamp** | **DateTime** | Date this session was started | 
**TimeToLive** | **long?** | Maximum session duration in minutes (0 is used for the infinite duration) | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

