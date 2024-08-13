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
pub struct ApplicationFilter {
    #[serde(rename = "CommandLine", skip_serializing_if = "Option::is_none")]
    pub command_line: Option<Vec<models::StringFilter>>,
    #[serde(rename = "Hashes", skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<models::HashFilter>>,
    #[serde(rename = "Path")]
    pub path: models::PathFilter,
    #[serde(rename = "Signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<models::SignatureFilter>,
    #[serde(rename = "WorkingDirectory", skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<models::PathFilter>,
}

impl ApplicationFilter {
    pub fn new(path: models::PathFilter) -> ApplicationFilter {
        ApplicationFilter {
            command_line: None,
            hashes: None,
            path,
            signature: None,
            working_directory: None,
        }
    }
}