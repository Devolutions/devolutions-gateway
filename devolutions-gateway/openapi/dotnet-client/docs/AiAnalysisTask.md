# Devolutions.Gateway.Client.Model.AiAnalysisTask
An AI analysis Task: the permanent record of one analysis the provisioner asked for  The work runs in the background; `state` and `payload` tell how it goes.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**CreatedAt** | **DateTime** | When the Task was created. | 
**DeadlineAt** | **DateTime** | Time at which a Task still unfinished fails; while the Task runs, it moves ahead each time an attempt starts or the Task makes progress. | 
**FinishedAt** | **DateTime?** | When it succeeded or failed. | [optional] 
**Id** | **Guid** | Task ID, chosen by the provisioner. | 
**Params** | [**AiAnalysisParams**](AiAnalysisParams.md) |  | 
**Payload** | [**AiAnalysisPayload**](AiAnalysisPayload.md) |  | [optional] 
**SessionId** | **Guid** | Recorded session the analysis is about. | 
**StartedAt** | **DateTime?** | When its first attempt started. | [optional] 
**State** | **TaskState** |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

