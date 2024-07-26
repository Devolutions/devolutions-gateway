# \DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**elevate_session_post**](DefaultApi.md#elevate_session_post) | **Post** /elevate/session | 
[**elevate_temporary_post**](DefaultApi.md#elevate_temporary_post) | **Post** /elevate/temporary | 
[**launch_post**](DefaultApi.md#launch_post) | **Post** /launch | 
[**logs_get**](DefaultApi.md#logs_get) | **Get** /logs | 
[**policy_assignments_get**](DefaultApi.md#policy_assignments_get) | **Get** /policy/assignments | 
[**policy_assignments_id_put**](DefaultApi.md#policy_assignments_id_put) | **Put** /policy/assignments/{id} | 
[**policy_me_get**](DefaultApi.md#policy_me_get) | **Get** /policy/me | 
[**policy_me_put**](DefaultApi.md#policy_me_put) | **Put** /policy/me | 
[**policy_profiles_get**](DefaultApi.md#policy_profiles_get) | **Get** /policy/profiles | 
[**policy_profiles_id_delete**](DefaultApi.md#policy_profiles_id_delete) | **Delete** /policy/profiles/{id} | 
[**policy_profiles_id_get**](DefaultApi.md#policy_profiles_id_get) | **Get** /policy/profiles/{id} | 
[**policy_profiles_id_put**](DefaultApi.md#policy_profiles_id_put) | **Put** /policy/profiles/{id} | 
[**policy_profiles_post**](DefaultApi.md#policy_profiles_post) | **Post** /policy/profiles | 
[**policy_rules_get**](DefaultApi.md#policy_rules_get) | **Get** /policy/rules | 
[**policy_rules_id_delete**](DefaultApi.md#policy_rules_id_delete) | **Delete** /policy/rules/{id} | 
[**policy_rules_id_get**](DefaultApi.md#policy_rules_id_get) | **Get** /policy/rules/{id} | 
[**policy_rules_id_put**](DefaultApi.md#policy_rules_id_put) | **Put** /policy/rules/{id} | 
[**policy_rules_post**](DefaultApi.md#policy_rules_post) | **Post** /policy/rules | 
[**revoke_post**](DefaultApi.md#revoke_post) | **Post** /revoke | 
[**status_get**](DefaultApi.md#status_get) | **Get** /status | 



## elevate_session_post

> elevate_session_post()


### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## elevate_temporary_post

> elevate_temporary_post(elevate_temporary_payload)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**elevate_temporary_payload** | [**ElevateTemporaryPayload**](ElevateTemporaryPayload.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## launch_post

> models::LaunchResponse launch_post(launch_payload)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**launch_payload** | [**LaunchPayload**](LaunchPayload.md) |  | [required] |

### Return type

[**models::LaunchResponse**](LaunchResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## logs_get

> Vec<models::ElevationResult> logs_get()


### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::ElevationResult>**](ElevationResult.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_assignments_get

> Vec<models::Assignment> policy_assignments_get()


### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::Assignment>**](Assignment.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_assignments_id_put

> policy_assignments_id_put(id, user)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |
**user** | [**Vec<models::User>**](User.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_me_get

> models::GetProfilesMeResponse policy_me_get()


### Parameters

This endpoint does not need any parameter.

### Return type

[**models::GetProfilesMeResponse**](GetProfilesMeResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_me_put

> policy_me_put(optional_id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**optional_id** | [**OptionalId**](OptionalId.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_profiles_get

> Vec<String> policy_profiles_get()


### Parameters

This endpoint does not need any parameter.

### Return type

**Vec<String>**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_profiles_id_delete

> policy_profiles_id_delete(id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_profiles_id_get

> models::Profile policy_profiles_id_get(id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |

### Return type

[**models::Profile**](Profile.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_profiles_id_put

> policy_profiles_id_put(id, profile)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |
**profile** | [**Profile**](Profile.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_profiles_post

> policy_profiles_post(profile)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**profile** | [**Profile**](Profile.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_rules_get

> Vec<String> policy_rules_get()


### Parameters

This endpoint does not need any parameter.

### Return type

**Vec<String>**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_rules_id_delete

> policy_rules_id_delete(id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_rules_id_get

> models::Rule policy_rules_id_get(id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |

### Return type

[**models::Rule**](Rule.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_rules_id_put

> policy_rules_id_put(id, rule)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** |  | [required] |
**rule** | [**Rule**](Rule.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_rules_post

> policy_rules_post(rule)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**rule** | [**Rule**](Rule.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## revoke_post

> revoke_post()


### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## status_get

> models::StatusResponse status_get()


### Parameters

This endpoint does not need any parameter.

### Return type

[**models::StatusResponse**](StatusResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

