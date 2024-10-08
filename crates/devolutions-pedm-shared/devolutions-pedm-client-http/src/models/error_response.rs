/*
 * Devolutions PEDM API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document:
 *
 * Generated by: https://openapi-generator.tech
 */

use crate::models;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(rename = "Kind")]
    pub kind: models::Error,
    #[serde(rename = "Win32Error")]
    pub win32_error: u32,
}

impl ErrorResponse {
    pub fn new(kind: models::Error, win32_error: u32) -> ErrorResponse {
        ErrorResponse { kind, win32_error }
    }
}
