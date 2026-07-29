# Devolutions.Gateway.Client.Model.GetUpdateScheduleResponse
Current auto-update schedule for Devolutions Agent.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Enabled** | **bool** | Enable periodic Devolutions Agent self-update checks. | 
**Interval** | **long** | Minimum interval between auto-update checks, in seconds.  &#x60;0&#x60; means check once at &#x60;UpdateWindowStart&#x60;. | 
**ManifestVersion** | **string** | Version of the &#x60;update_status.json&#x60; format in &#x60;\&quot;major.minor\&quot;&#x60; form (e.g. &#x60;\&quot;1.1\&quot;&#x60;). | 
**Products** | **List&lt;string&gt;** | Products the agent autonomously polls for new versions. | [optional] 
**UpdateWindowEnd** | **int?** | End of the maintenance window as seconds past midnight (local time, exclusive). &#x60;None&#x60; means no upper bound (single check at &#x60;UpdateWindowStart&#x60;). | [optional] 
**UpdateWindowStart** | **int** | Start of the maintenance window as seconds past midnight (local time). | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

