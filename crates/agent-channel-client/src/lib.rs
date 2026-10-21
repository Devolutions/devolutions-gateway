//! The agent's side of the agent channel ([CONTRACT.agent-identity.md §7 "Channel (gRPC)"][contract]).
//!
//! [`ChannelClient::connect`] keeps one stream open to an authority: it opens and authenticates the stream, reports
//! the authority's messages as [`Event`]s, and reopens the stream after a transient closure.
//! The caller decides what the messages and closures mean for the identity.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#7-channel-grpc

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use device_key::DeviceKey;
use http_client_proxy::ProxyConfig;
use rustls::pki_types::CertificateDer;
use tokio::sync::mpsc;
use url::Url;

use crate::transport::Transport;

mod backoff;
mod closure;
mod stream;
mod transport;

pub use crate::backoff::{Backoff, uniform_jitter};
pub use crate::closure::{Closure, ClosureClass, TerminalCode, TransientKind};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const OPENING_TIMEOUT: Duration = Duration::from_secs(30);

/// Opens agent channels.
pub struct ChannelClient {
    shared: Arc<Shared>,
}

struct Shared {
    transport: Transport,
    settings: Settings,
}

/// Timing settings of a [`ChannelClient`].
pub struct Settings {
    /// Interval between HTTP/2 keepalive pings.
    pub keepalive_interval: Duration,
    /// Time allowed from the TCP connection to `Welcome`.
    pub opening_timeout: Duration,
    /// When a closed stream is opened again.
    pub backoff: Backoff,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            keepalive_interval: KEEPALIVE_INTERVAL,
            opening_timeout: OPENING_TIMEOUT,
            backoff: Backoff::default(),
        }
    }
}

/// The authority and identity a channel connects with.
pub struct Target {
    /// The identity's `agent_channel_url`.
    pub url: Url,
    /// The device key that signs the opening request and the channel proof.
    pub key: Arc<dyn DeviceKey>,
    /// The leaf certificate of `key`, whose thumbprint names the key to the authority.
    pub leaf_certificate_der: Vec<u8>,
    /// Supplies the `Hello` content each time a stream sends one.
    pub hello: Arc<dyn Fn() -> HelloFields + Send + Sync>,
}

/// The caller-supplied part of a `Hello`, collected when it is sent.
pub struct HelloFields {
    /// The agent's metadata ([CONTRACT.agent-identity.md §3.1 "Metadata sent by the agent"][contract]).
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#31-metadata-sent-by-the-agent
    pub metadata: HashMap<String, String>,
    /// The stored `config.revision`, sent as `applied_state_versions["config"]`.
    pub config_revision: u64,
}

/// What a channel reports to its caller.
///
/// Each `id` an event carries is a lowercase hyphenated UUID: the channel closes a stream on a message whose `id` is
/// not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// The authority answered the `Hello` with `Welcome`: the stream is authenticated.
    Authenticated,
    /// The authority asks the identity to renew; the caller acknowledges `id`.
    RenewRequested { id: String, reason: String },
    /// The authority asks for a new stream, which the caller opens before dropping this channel.
    Reconnect { id: String, reason: String },
    /// A newer effective config, as a JSON object; the caller acknowledges `id`.
    ConfigUpdate { id: String, config_json: String },
    /// The stream closed or its opening failed.
    ///
    /// The channel opens a new stream after `reopen_after`; without one, the channel has stopped.
    Closed {
        closure: Closure,
        reopen_after: Option<Duration>,
    },
}

/// One channel: a stream that is reopened after each transient closure.
///
/// Dropping the channel closes it: an opening, or a wait to reopen, stops at once, and an authenticated stream ends
/// once the acknowledgements queued before are sent.
pub struct Channel {
    events: mpsc::Receiver<Event>,
    /// Dropping it tells the stream task to stop.
    acks: mpsc::UnboundedSender<String>,
}

impl ChannelClient {
    /// Creates a client that trusts the OS trust store plus `extra_trusted_roots`, and connects through `proxy`.
    pub fn new(
        proxy: ProxyConfig,
        extra_trusted_roots: &[CertificateDer<'_>],
        settings: Settings,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            shared: Arc::new(Shared {
                transport: Transport::new(proxy, extra_trusted_roots)?,
                settings,
            }),
        })
    }

    /// Starts a channel to `target`; it must be called within a Tokio runtime.
    ///
    /// The channel runs over HTTP/2 and TLS, so `target.url` must be an `https` URL with a host.
    pub fn connect(&self, target: Target) -> anyhow::Result<Channel> {
        anyhow::ensure!(target.url.scheme() == "https", "channel URL is not https");
        transport::endpoint(&target.url)?;
        let (event_sender, events) = mpsc::channel(16);
        let (acks, ack_receiver) = mpsc::unbounded_channel();
        tokio::spawn(stream::run(
            Arc::clone(&self.shared),
            target,
            event_sender,
            ack_receiver,
        ));
        Ok(Channel { events, acks })
    }
}

impl Channel {
    /// Waits for the next event, or returns `None` once the channel has stopped.
    pub async fn next_event(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// Acknowledges the authority's message `correlation_id` ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract]).
    ///
    /// Only an authenticated stream carries acknowledgements, and one sent without such a stream is dropped: the
    /// authority repeats a renewal request on the next stream, and `Hello` reconciles the config.
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
    pub fn ack(&self, correlation_id: &str) {
        let _ = self.acks.send(correlation_id.to_owned());
    }
}

#[cfg(test)]
mod tests;
