//! High-level AI for Devolutions Gateway: one method per purpose, never a raw request to a model.
//!
//! A purpose is one AI job Gateway needs done, such as listing what a user did in a session transcript with
//! [`AiClient::describe_session_actions`].
//! The crate does not expose low-level AI requests: there is no chat, no completion call, and no way to pass a prompt.
//! A consumer states what it needs and gets a typed result; it is not expected to know, or care, how the result is
//! obtained.
//!
//! Behind each purpose, the crate owns everything about talking to the model:
//! - the prompt and its version, which a consumer that stores the results should store with them;
//! - the HTTP API of each provider and its quirks: OpenAI chat completions (also spoken by Mistral, Gemini and many
//!   others) and Anthropic Messages;
//! - the request limits: the output token limit, and a timeout, since requests are not streamed;
//! - reading the answer: reasoning blocks are dropped, and an answer the provider refused or cut short is an error,
//!   so only whole answers are parsed;
//! - turning the model text into typed output;
//! - keeping the API key out of logs and errors, and telling which errors are worth retrying with
//!   [`Error::is_transient`].
//!
//! A consumer only gives an [`AiClient`] the provider settings (provider, model, API key, and its own HTTP client, so
//! its proxy and TLS policy apply) and gives each purpose its input.
//! Every purpose returns a [`Response`]: the output, the model that answered, and the tokens used.
//!
//! The provider APIs are implemented here on purpose, rather than through a general LLM crate, to keep dependencies
//! small. Only what the purposes need is supported: one non-streamed text request per call, without chat history,
//! tools, or embeddings.
//!
//! A new purpose is a module like [`session_actions`]: its prompt and `PROMPT_VERSION`, a request builder returned by
//! a new [`AiClient`] method, and the parser of the answer.

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
