# \DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**about_get**](DefaultApi.md#about_get) | **Get** /about | 
[**launch_post**](DefaultApi.md#launch_post) | **Post** /launch | 
[**log_jit_get**](DefaultApi.md#log_jit_get) | **Get** /log/jit | 
[**log_jit_id_get**](DefaultApi.md#log_jit_id_get) | **Get** /log/jit/{id} | 
[**policy_assignments_get**](DefaultApi.md#policy_assignments_get) | **Get** /policy/assignments | 
[**policy_assignments_id_put**](DefaultApi.md#policy_assignments_id_put) | **Put** /policy/assignments/{id} | 
[**policy_me_get**](DefaultApi.md#policy_me_get) | **Get** /policy/me | 
[**policy_me_id_put**](DefaultApi.md#policy_me_id_put) | **Put** /policy/me/{id} | 
[**policy_profiles_get**](DefaultApi.md#policy_profiles_get) | **Get** /policy/profiles | 
[**policy_profiles_id_delete**](DefaultApi.md#policy_profiles_id_delete) | **Delete** /policy/profiles/{id} | 
[**policy_profiles_id_get**](DefaultApi.md#policy_profiles_id_get) | **Get** /policy/profiles/{id} | 
[**policy_profiles_post**](DefaultApi.md#policy_profiles_post) | **Post** /policy/profiles | 
[**policy_users_get**](DefaultApi.md#policy_users_get) | **Get** /policy/users | 



## about_get

> models::AboutData about_get()


### Parameters

This endpoint does not need any parameter.

### Return type

[**models::AboutData**](AboutData.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
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


## log_jit_get

> models::JitElevationLogPage log_jit_get(jit_elevation_log_query_options)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**jit_elevation_log_query_options** | [**JitElevationLogQueryOptions**](JitElevationLogQueryOptions.md) |  | [required] |

### Return type

[**models::JitElevationLogPage**](JitElevationLogPage.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## log_jit_id_get

> models::JitElevationLogRow log_jit_id_get(id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **i64** |  | [required] |

### Return type

[**models::JitElevationLogRow**](JitElevationLogRow.md)

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
**id** | **i64** |  | [required] |
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


## policy_me_id_put

> policy_me_id_put(id)


### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **i64** |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## policy_profiles_get

> Vec<i64> policy_profiles_get()


### Parameters

This endpoint does not need any parameter.

### Return type

**Vec<i64>**

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
**id** | **i64** |  | [required] |

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
**id** | **i64** |  | [required] |

### Return type

[**models::Profile**](Profile.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
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


## policy_users_get

> Vec<models::User> policy_users_get()


### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::User>**](User.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

