# Devolutions.Gateway.Client.Model.AiAnalysisRequest
Settings of an AI analysis

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ApiKey** | **string** | API key of the provider, kept in memory only until the Task ends. | 
**BaseUrl** | **string** | Endpoint of the provider API, kept in memory only; required for &#x60;openai-compatible&#x60;. | [optional] 
**MaxOutputTokens** | **int?** | Upper bound of tokens in each AI answer. | [optional] 
**Model** | **string** | Model identifier, passed to the provider as is. | 
**Provider** | **AiProvider** |  | 
**TaskId** | **Guid** | Task ID, chosen by the caller so it can send the same request again safely. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

