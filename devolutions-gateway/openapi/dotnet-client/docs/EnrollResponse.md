# Devolutions.Gateway.Client.Model.EnrollResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AgentId** | **Guid** | Assigned agent ID. | 
**ClientCertPem** | **string** | PEM-encoded client certificate (signed by the gateway CA). | 
**GatewayCaCertPem** | **string** | PEM-encoded gateway CA certificate (for server verification). | 
**QuicEndpoint** | **string** | QUIC endpoint to connect to (&#x60;host:port&#x60;). | 
**ServerSpkiSha256** | **string** | SHA-256 hash of the server certificate&#39;s SPKI (hex-encoded). Used by the agent to pin the server&#39;s public key. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

