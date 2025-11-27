//! Provider configuration builder for AI providers.

use std::collections::HashMap;

/// Authentication method for the AI provider.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Bearer token in Authorization header
    Bearer,
    /// Custom header for API key
    Header(String),
}

/// Configuration for an AI provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub api_key_required: bool,
    pub auth_method: AuthMethod,
    pub extra_headers: HashMap<String, String>,
}

/// Builder for provider configuration.
#[derive(Debug, Default)]
pub struct ProviderConfigBuilder {
    name: Option<String>,
    endpoint: Option<String>,
    api_key: Option<String>,
    api_key_required: bool,
    auth_method: Option<AuthMethod>,
    extra_headers: HashMap<String, String>,
}

impl ProviderConfigBuilder {
    /// Create a new provider configuration builder.
    pub fn new() -> Self {
        Self {
            api_key_required: true, // Default to requiring API key
            ..Default::default()
        }
    }

    /// Set the provider name.
    #[must_use]
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Set the provider endpoint.
    #[must_use]
    pub fn endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Set the API key.
    #[must_use]
    pub fn api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key;
        self
    }

    /// Set whether an API key is required.
    #[must_use]
    pub fn api_key_required(mut self, required: bool) -> Self {
        self.api_key_required = required;
        self
    }

    /// Use Bearer authentication (Authorization: Bearer <token>).
    #[must_use]
    pub fn bearer_auth(mut self) -> Self {
        self.auth_method = Some(AuthMethod::Bearer);
        self
    }

    /// Use a custom header for authentication.
    #[must_use]
    pub fn header_auth(mut self, header_name: &str) -> Self {
        self.auth_method = Some(AuthMethod::Header(header_name.to_owned()));
        self
    }

    /// Add an extra header to be included in all requests.
    #[must_use]
    pub fn extra_header(mut self, name: &str, value: &str) -> Self {
        self.extra_headers.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Build the provider configuration.
    pub fn build(self) -> Result<ProviderConfig, &'static str> {
        let name = self.name.ok_or("provider name is required")?;
        let endpoint = self.endpoint.ok_or("provider endpoint is required")?;
        let auth_method = self.auth_method.ok_or("auth method is required")?;

        Ok(ProviderConfig {
            name,
            endpoint,
            api_key: self.api_key,
            api_key_required: self.api_key_required,
            auth_method,
            extra_headers: self.extra_headers,
        })
    }
}
