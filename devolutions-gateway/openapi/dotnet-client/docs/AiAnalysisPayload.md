# Devolutions.Gateway.Client.Model.AiAnalysisPayload
Details of the state of an AI analysis Task: `running`, `succeeded` and `failed` each have their own

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Done** | **long?** | Work done in the step: bytes read while &#x60;reading&#x60;, parts described while &#x60;describing&#x60;; absent in the other steps. | [optional] 
**Step** | **string** | Current step: &#x60;preparing&#x60; (the attempt starts), &#x60;reading&#x60; (the recordings are read), &#x60;describing&#x60; (the AI is asked about the recording, part by part), then &#x60;writing&#x60; (the log is written). | 
**Total** | **long?** | Work the step has in all, in the same unit as &#x60;done&#x60;; absent in the other steps. | [optional] 
**Usage** | [**AiAnalysisUsage**](AiAnalysisUsage.md) |  | 
**FileName** | **string** | Name of the log in the session manifest, such as &#x60;ai-analysis-0.slog&#x60;. | 
**Model** | **string** | Model that wrote the log, as reported by the AI provider; the requested model when it reports none. | 
**PromptVersion** | **string** | Versions of the prompts that wrote the log, such as &#x60;session-actions-3f9a1c2b7e4d0a51+session-summary-8b20e9a4c1f70d36&#x60;. | 
**Error** | [**AiAnalysisError**](AiAnalysisError.md) |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

