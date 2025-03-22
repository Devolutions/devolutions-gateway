# Devolutions.Gateway.Client.Model.PreflightOutput

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AgentVersion** | **string** | Agent service version, if installed.  Set for \&quot;agent-version\&quot; kind. | [optional] 
**AlertMessage** | **string** | Message describing the problem.  Set for \&quot;alert\&quot; kind. | [optional] 
**AlertStatus** | **PreflightAlertStatus** |  | [optional] 
**Kind** | **PreflightOutputKind** |  | 
**OperationId** | **Guid** | The ID of the preflight operation associated to this result. | 
**RecordingStorageAvailableSpace** | **long?** | The remaining available space to store recordings, in bytes.  set for \&quot;recording-storage-health\&quot; kind. | [optional] 
**RecordingStorageIsWriteable** | **bool?** | Whether the recording storage is writeable or not.  Set for \&quot;recording-storage-health\&quot; kind. | [optional] 
**RecordingStorageTotalSpace** | **long?** | The total space of the disk used to store recordings, in bytes.  Set for \&quot;recording-storage-health\&quot; kind. | [optional] 
**ResolvedAddresses** | **List&lt;string&gt;** | Resolved IP addresses.  Set for \&quot;resolved-host\&quot; kind. | [optional] 
**ResolvedHost** | **string** | Hostname that was resolved.  Set for \&quot;resolved-host\&quot; kind. | [optional] 
**RunningSessionCount** | **int?** | Number of running sessions.  Set for \&quot;running-session-count\&quot; kind. | [optional] 
**VarVersion** | **string** | Service version.  Set for \&quot;version\&quot; kind. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

