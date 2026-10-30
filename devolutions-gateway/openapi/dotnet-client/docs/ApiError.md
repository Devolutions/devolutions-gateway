# Devolutions.Gateway.Client.Model.ApiError
Body of an API error response, as defined by RFC 9457 (problem details for HTTP APIs).  The Gateway logs the details of the error, along with its code.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Error** | **string** | Machine-readable error code; the &#x60;ErrorCode&#x60; schema lists the known values.  New codes can be added: treat unknown values as generic failures. | 
**Status** | **int** | HTTP status code. | 
**Title** | **string** | Reason phrase of the HTTP status. | 
**Type** | **string** | Problem type, always &#x60;about:blank&#x60;: the HTTP status and the error code describe the problem. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

