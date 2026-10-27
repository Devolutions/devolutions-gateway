# Devolutions.Gateway.Client.Model.AiAnalysisRunningPayload
Payload of a `running` AI analysis Task: its progress, and the tokens it used so far

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Done** | **long?** | Work done in the step: bytes read while &#x60;reading&#x60;, parts described while &#x60;describing&#x60;; absent in the other steps. | [optional] 
**Step** | **string** | Current step: &#x60;preparing&#x60; (the attempt starts), &#x60;reading&#x60; (the recordings are read), &#x60;describing&#x60; (the AI is asked about the recording, part by part), then &#x60;writing&#x60; (the log is written). | 
**Total** | **long?** | Work the step has in all, in the same unit as &#x60;done&#x60;; absent in the other steps. | [optional] 
**Usage** | [**AiAnalysisUsage**](AiAnalysisUsage.md) |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

