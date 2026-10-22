# Devolutions.Gateway.Client.Model.AiAnalysisSucceededPayload
Payload of a `succeeded` AI analysis Task: the log it added to the session

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileName** | **string** | Name of the new log in the session manifest, such as &#x60;ai-analysis-0.slog&#x60;. | 
**Model** | **string** | Model that wrote the log, as reported by the AI provider; the requested model when it reports none. | 
**PromptVersion** | **string** | Versions of the prompts that wrote the log, such as &#x60;session-actions-3f9a1c2b7e4d0a51+session-summary-8b20e9a4c1f70d36&#x60;. | 
**Usage** | [**AiAnalysisUsage**](AiAnalysisUsage.md) |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

