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
pub struct StartupInfoDto {
    #[serde(rename = "Desktop", skip_serializing_if = "Option::is_none")]
    pub desktop: Option<String>,
    #[serde(rename = "FillAttribute")]
    pub fill_attribute: u32,
    #[serde(rename = "Flags")]
    pub flags: u32,
    #[serde(rename = "ParentPid", skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(rename = "ShowWindow")]
    pub show_window: u32,
    #[serde(rename = "Title", skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "X")]
    pub x: u32,
    #[serde(rename = "XCountChars")]
    pub x_count_chars: u32,
    #[serde(rename = "XSize")]
    pub x_size: u32,
    #[serde(rename = "Y")]
    pub y: u32,
    #[serde(rename = "YCountChars")]
    pub y_count_chars: u32,
    #[serde(rename = "YSize")]
    pub y_size: u32,
}

impl StartupInfoDto {
    pub fn new(
        fill_attribute: u32,
        flags: u32,
        show_window: u32,
        x: u32,
        x_count_chars: u32,
        x_size: u32,
        y: u32,
        y_count_chars: u32,
        y_size: u32,
    ) -> StartupInfoDto {
        StartupInfoDto {
            desktop: None,
            fill_attribute,
            flags,
            parent_pid: None,
            show_window,
            title: None,
            x,
            x_count_chars,
            x_size,
            y,
            y_count_chars,
            y_size,
        }
    }
}
