# Devolutions.Gateway.Client.Model.ClaimedTrafficEvent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ActiveDurationMs** | **long** | Total duration the traffic item was active (milliseconds) | 
**BytesRx** | **long** | Total bytes received from the remote peer | 
**BytesTx** | **long** | Total bytes transmitted to the remote peer | 
**ConnectAtMs** | **long** | Timestamp when the connection attempt began (epoch milliseconds) | 
**DisconnectAtMs** | **long** | Timestamp when the traffic item was closed or connection failed (epoch milliseconds) | 
**Outcome** | **EventOutcomeResponse** |  | 
**Protocol** | **TransportProtocolResponse** |  | 
**SessionId** | **Guid** | Unique identifier for the session/tunnel this traffic item belongs to | 
**TargetHost** | **string** | Original target host string before DNS resolution | 
**TargetIp** | **string** | Concrete target IP address after resolution | 
**TargetPort** | **int** | Target port number for the connection | 
**Id** | **string** | Database ID of the claimed event (used for acknowledgment, ULID format) | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

