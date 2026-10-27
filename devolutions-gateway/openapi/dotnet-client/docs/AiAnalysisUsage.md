# Devolutions.Gateway.Client.Model.AiAnalysisUsage
Tokens the AI provider counted for an AI analysis Task, over all its attempts

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**InputTokens** | **long** |  | 
**OutputTokens** | **long** |  | 
**UnreportedRequests** | **long** | Requests that may have cost tokens the provider did not report, such as a request that got no answer, or one still waiting for it; while it is not 0, &#x60;inputTokens&#x60; and &#x60;outputTokens&#x60; are short of what the provider billed. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

