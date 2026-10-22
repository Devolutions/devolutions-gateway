# Devolutions.Gateway.Client.Model.RecordingSearchRequest
What to search for, and in which recordings.  Unknown fields are rejected, so that an option added later is never silently ignored by a Gateway that predates it.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Cursor** | **string** | Where the page starts: the &#x60;nextCursor&#x60; of the previous page, sent unchanged with the same &#x60;query&#x60;, &#x60;recordings&#x60; and &#x60;startTime&#x60;. | [optional] 
**MaxHits** | **int?** | Most hits in the page, from 1 to 1000; 1000 when missing. | [optional] 
**Query** | **string** | Text to search for, ignoring case; leading and trailing spaces are part of it, and an empty text matches every line. | 
**Recordings** | [**RecordingSelection**](RecordingSelection.md) |  | 
**StartTime** | [**StartTimeRange**](StartTimeRange.md) |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

