# Devolutions.Gateway.Client.Model.RecordingSearchHit
A line that matches the search text.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileName** | **string** | Name of the &#x60;.slog&#x60; artifact holding the line, as listed in &#x60;recording.json&#x60;. | 
**Line** | **string** | The line&#39;s text without its line break; bytes that are not UTF-8 read as U+FFFD. | 
**LineNumber** | **long** | Number of the line in the file, counting from 1. | 
**Offset** | **long** | Byte offset of the line in the file. | 
**RecordingId** | **Guid** | The recording whose artifact holds the line. | 
**Truncated** | **bool** | The line is longer than 256 KiB, so &#x60;line&#x60; holds only its start, and the file holds the rest. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

