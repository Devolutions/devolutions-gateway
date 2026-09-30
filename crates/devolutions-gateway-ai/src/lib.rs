//! AI requests for Devolutions Gateway, one method per purpose.
//!
//! A purpose is one job Gateway gives to an AI model, such as listing the actions of a session transcript with
//! [`AiClient::describe_session_actions`].
//! Each purpose owns its prompt, the version of that prompt, and the parser of the answer, so Gateway gets typed
//! results and never writes a prompt or reads raw model text.
//! Every purpose goes through one [`AiClient`], which holds the provider settings, and returns a [`Response`], which
//! also tells which model answered and how many tokens the request used.
//!
//! Each provider is reached through its own HTTP API: OpenAI chat completions (also spoken by Mistral, Gemini and many
//! others) or Anthropic Messages. Only the few fields a single text completion needs are modeled.
//! Requests are not streamed and are bounded by a timeout.
//!
//! A new purpose is a module like [`session_actions`]: a prompt and its `PROMPT_VERSION`, a request builder returned by
//! a new [`AiClient`] method, and a parser turning the answer into typed output.

mod client;
mod error;
mod response;
pub mod session_actions;
mod wire;

pub use reqwest;
pub use secrecy;

pub use self::client::{AiClient, AiClientBuilder, BuildError, DEFAULT_REQUEST_TIMEOUT, Provider};
pub use self::error::Error;
pub use self::response::{Response, Usage};
