# Devolutions.Gateway.Client.Model.RecordingLogSearchResponse
Session Recording Log search result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Hits** | [**List&lt;RecordingLogSearchHit&gt;**](RecordingLogSearchHit.md) | Matching entries, ordered by recording, then by manifest file order, then by line | 
**LimitReached** | **bool** | The hit limit or the response size bound was reached, so more matches may exist | 
**NotFoundRecordingIds** | **List&lt;Guid&gt;** | Listed recordings that are not stored on this instance or have no readable manifest | 
**ScanLimitReached** | **bool** | A scan bound was reached, so some entries were not searched | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

