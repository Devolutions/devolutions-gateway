# Devolutions.Gateway.Client.Model.StartTimeRange
A range of recording start times, as written in `recording.json`, that includes `from` and excludes `to`.  A missing end leaves that side of the range open.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**From** | **DateTime?** | Earliest start time searched. | [optional] 
**To** | **DateTime?** | Recordings that start at this time or later are not searched. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

