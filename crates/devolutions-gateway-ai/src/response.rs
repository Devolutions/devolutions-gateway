use core::ops::Add;

use crate::Error;

/// Answer to a purpose request.
#[derive(Debug, Clone, PartialEq)]
pub struct Response<T> {
    /// Result of the purpose, such as the actions of a session.
    pub output: T,
    /// Model that answered, as reported by the provider.
    ///
    /// It is often more precise than the requested model, such as a dated version of it.
    pub model: Option<String>,
    /// Tokens the provider counted for the request, when it reports them.
    pub usage: Option<Usage>,
}

impl<T> Response<T> {
    pub(crate) fn try_map<U>(self, f: impl FnOnce(T) -> Result<U, Error>) -> Result<Response<U>, Error> {
        Ok(Response {
            output: f(self.output)?,
            model: self.model,
            usage: self.usage,
        })
    }
}

/// Tokens counted by the provider for one or more requests; providers bill by them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Tokens of the prompt and the input.
    pub input_tokens: u64,
    /// Tokens of the answer.
    pub output_tokens: u64,
}

impl Add for Usage {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            input_tokens: self.input_tokens.saturating_add(other.input_tokens),
            output_tokens: self.output_tokens.saturating_add(other.output_tokens),
        }
    }
}
