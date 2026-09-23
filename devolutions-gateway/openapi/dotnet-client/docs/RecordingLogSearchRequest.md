# Devolutions.Gateway.Client.Model.RecordingLogSearchRequest
Session Recording Log search request

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**CaseSensitive** | **bool** | Match case exactly instead of ignoring case | [optional] 
**EventTypes** | **List&lt;string&gt;** | When not empty, only entries whose &#x60;event&#x60; is one of these values are considered | [optional] 
**From** | **DateTime?** | Only entries whose &#x60;timestamp&#x60; is at or after this instant are considered | [optional] 
**Limit** | **int?** | Maximum number of hits to return (default 100, capped at 1000) | [optional] 
**Query** | **string** | Text to look for; an empty query matches every entry | [optional] 
**RecordingIds** | **List&lt;Guid&gt;** | Recordings to search, in the order results are returned  When omitted, every recording stored on this instance is searched, newest first. An empty list searches nothing. | [optional] 
**To** | **DateTime?** | Only entries whose &#x60;timestamp&#x60; is before this instant are considered | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

