# Devolutions.Gateway.Client.Model.SessionTokenSignRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ContentType** | **SessionTokenContentType** |  | 
**Destination** | **string** | Destination host. | [optional] 
**KrbKdc** | **string** | Kerberos KDC address.  E.g.: &#x60;tcp://IT-HELP-DC.ad.it-help.ninja:88&#x60;. Default scheme is &#x60;tcp&#x60;. Default port is &#x60;88&#x60;. | [optional] 
**KrbRealm** | **string** | Kerberos realm.  E.g.: &#x60;ad.it-help.ninja&#x60;. Should be lowercased (actual validation is case-insensitive though). | [optional] 
**Lifetime** | **long** | The validity duration in seconds for the session token.  This value cannot exceed 2 hours. | 
**Protocol** | **string** | Protocol for the session (e.g.: \&quot;rdp\&quot;). | [optional] 
**SessionId** | **Guid?** | Unique ID for this session. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

