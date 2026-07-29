# Devolutions.Gateway.Client.Model.SetUpdateScheduleRequest
Desired auto-update schedule to apply to Devolutions Agent.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Enabled** | **bool** | Enable periodic Devolutions Agent self-update checks. | 
**Interval** | **long** | Minimum interval between auto-update checks, in seconds.  &#x60;0&#x60; means check once at &#x60;UpdateWindowStart&#x60; (default). | [optional] 
**Products** | **List&lt;string&gt;** | Products the agent autonomously polls for new versions (default: empty). | [optional] 
**UpdateWindowEnd** | **int?** | End of the maintenance window as seconds past midnight in local time, exclusive.  &#x60;null&#x60; (default) means no upper bound - a single check fires at &#x60;UpdateWindowStart&#x60;. When end &lt; start the window crosses midnight. | [optional] 
**UpdateWindowStart** | **int** | Start of the maintenance window as seconds past midnight in local time (default: &#x60;7200&#x60; &#x3D; 02:00). | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

