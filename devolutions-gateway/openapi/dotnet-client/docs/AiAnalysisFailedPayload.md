# Devolutions.Gateway.Client.Model.AiAnalysisFailedPayload
Payload of a `failed` AI analysis Task: why it failed

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Attempts** | **int** | Number of attempts started. | 
**Details** | **Object** | What went wrong: a text, except for &#x60;timed out&#x60;, where it is &#x60;{ \&quot;lastPayload\&quot;: &lt;payload before the timeout&gt; }&#x60;. | 
**Reason** | **string** | Kind of failure, such as &#x60;permanent error&#x60;, &#x60;attempts exhausted&#x60;, &#x60;key lost&#x60; or &#x60;timed out&#x60;. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

