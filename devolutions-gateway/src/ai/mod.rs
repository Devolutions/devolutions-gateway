//! AI module for provider configuration and utilities.
//!
//! This module contains shared types and utilities for AI provider integration.

mod provider;

#[rustfmt::skip]
pub use provider::{AuthMethod, ProviderConfig, ProviderConfigBuilder};
