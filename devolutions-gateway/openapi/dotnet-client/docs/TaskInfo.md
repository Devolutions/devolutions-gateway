# Devolutions.Gateway.Client.Model.TaskInfo
A background task and its status.  `substate` is set only when `state` is `running`, `result` only when it is `success`, and `error` only when it is `failed`. Both `substate` and `result` are kind-specific: for `ai-log`, `substate` is an `AiLogSubstate`.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Error** | **string** | Why the task failed. | [optional] 
**Id** | **Guid** | Task ID. | 
**Kind** | **string** | Task kind, as in the &#x60;jet_tk&#x60; claim of the TASK token. | 
**Result** | **Object** | Result of a successful task. | [optional] 
**State** | **TaskState** |  | 
**Substate** | **Object** | Progress of a running task. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

