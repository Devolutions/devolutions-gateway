# Devolutions.Gateway.Client.Model.RecordingSearchResponse
The lines that match the search text.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Hits** | [**List&lt;RecordingSearchHit&gt;**](RecordingSearchHit.md) | Matching lines, newest recording first when searching all recordings, otherwise in the requested order. | 
**NextCursor** | **string** | Where the next page starts; absent when every log has been read.  The cursor is opaque, and its format may change between versions. A page with fewer hits than asked for may still be followed by more pages. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

