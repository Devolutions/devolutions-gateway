# Devolutions.Gateway.Client.Model.AiAnalysisParams
Params of an AI analysis Task: what was asked, without the API key and the base URL

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Language** | **string** | Language the AI writes in; absent when not asked, so the AI writes in English. | [optional] 
**MaxOutputTokens** | **long?** | Upper bound of tokens in each AI answer; null when not asked. | [optional] 
**Model** | **string** | Model identifier, passed to the provider as is. | 
**Provider** | **AiProvider** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

