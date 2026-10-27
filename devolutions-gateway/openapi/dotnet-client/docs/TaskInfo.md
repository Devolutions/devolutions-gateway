# Devolutions.Gateway.Client.Model.TaskInfo
A Task: the permanent record of one piece of work the provisioner asked Gateway to do  The work runs in the background; `state` and `payload` tell how it goes. The shape of `params` and `payload` belongs to the kind. For `recording-ai-analysis`, `params` is an `AiAnalysisParams`, and `payload` is an `AiAnalysisRunningPayload` while `running`, an `AiAnalysisSucceededPayload` once `succeeded`, and an `AiAnalysisFailedPayload` once `failed`.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Attempts** | **int** | Number of attempts started so far. | 
**CreatedAt** | **DateTime** | When the Task was created. | 
**DeadlineAt** | **DateTime** | Time at which a Task still unfinished fails; while the Task runs, it moves ahead each time an attempt starts or the Task makes progress. | 
**FinishedAt** | **DateTime?** | When it succeeded or failed. | [optional] 
**Id** | **Guid** | Task ID, chosen by the provisioner. | 
**Kind** | **string** | Kind of work, such as &#x60;recording-ai-analysis&#x60;. | 
**Params** | **Object** | What was asked, without secrets. | 
**Payload** | **Object** | Details of the current state; null while &#x60;queued&#x60;. | [optional] 
**StartedAt** | **DateTime?** | When its first attempt started. | [optional] 
**State** | **TaskState** |  | 
**Target** | **string** | What the work is about, such as a session ID. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

