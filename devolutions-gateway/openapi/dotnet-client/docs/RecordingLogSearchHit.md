# Devolutions.Gateway.Client.Model.RecordingLogSearchHit
One Session Recording Log entry matching the search

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Entry** | **Object** | The entry, exactly as written in the file | 
**FileName** | **string** | Name of the &#x60;.slog&#x60; file containing the entry | 
**LineNumber** | **int** | One-based line number of the entry in the file | 
**MatchedFields** | [**List&lt;RecordingLogSearchField&gt;**](RecordingLogSearchField.md) | Fields matched by the query; empty when the query is empty | 
**RecordingId** | **Guid** | Recording containing the entry | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

