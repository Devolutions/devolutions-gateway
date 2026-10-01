# Devolutions.Gateway.Client.Model.AiLogParams
AI settings used by an `ai-log` task: the body of `POST /jet/tasks` for a TASK token of kind `ai-log`.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ApiKey** | **string** | Kept in memory for this task only. | 
**BaseUrl** | **string** | Overrides the provider default; required for &#x60;openai-compatible&#x60;. | [optional] 
**MaxOutputTokens** | **int?** | Upper bound of tokens in each AI answer. | [optional] 
**Model** | **string** | Model identifier, passed to the provider as is. | 
**Provider** | **AiProvider** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

