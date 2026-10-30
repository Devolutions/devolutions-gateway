# Devolutions.Gateway.Client.Model.AiAnalysisError
Why an AI analysis Task failed: a kind, with the fields of that kind; there is no text for people, so the caller words it

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**File** | **string** | Recording file that cannot be read, for &#x60;unreadableRecording&#x60;. | [optional] 
**Kind** | **AiAnalysisErrorKind** |  | 
**Last** | [**AiAnalysisRecoverableError**](AiAnalysisRecoverableError.md) |  | [optional] 
**Status** | **int?** | HTTP status the AI provider answered, for &#x60;aiRejected&#x60;. | [optional] 
**Why** | **AiAnalysisBadAnswer** |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

