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
pub struct HashFilter {
    #[serde(rename = "Sha1", skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(rename = "Sha256", skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl HashFilter {
    pub fn new() -> HashFilter {
        HashFilter {
            sha1: None,
            sha256: None,
        }
    }
}
