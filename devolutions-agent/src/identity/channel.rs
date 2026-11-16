//! The agent channel of one identity ([CONTRACT.agent-identity.md §7 "Channel (gRPC)"][contract]): the stream in use,
//! and the stream that replaces it.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#7-channel-grpc

use std::collections::BTreeSet;
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use agent_channel_client::{Channel, Closure, ClosureClass, ErrorCode, Event, Reporter, TerminalCode};
use agent_identity::client;
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

use super::runner::config_revision;
use crate::device_management::DeviceManagementContext;

/// The most acknowledgements a queued config holds, its own included.
///
/// A burst of pushes larger than this while the runner is busy loses the acknowledgements of the configs past it;
/// `Hello` reconciles the config of the next stream anyway ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract]).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
const MAX_CONFIG_ACKS: usize = 32;

/// What the identity needs from its agent channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Want {
    /// No stream.
    Nothing,
    /// No stream opens, because the outcome of a `confirm` may be unknown, and an authenticated stream stays in use
    /// ([CONTRACT.agent-identity.md §8.1 "Agent renewal"][contract], steps 3–4).
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#81-agent-renewal
    Hold,
    /// A stream to `url`, opened with the key `key_name`.
    Stream { url: Url, key_name: String },
}

/// What a stream event asks of the identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Notice {
    /// The identity no longer has an authenticated stream.
    Lost,
    /// A stream must be opened for what the identity wants, for example after the authority asked for a new one.
    StreamNeeded,
    /// The authority ended the identity.
    Terminal(TerminalCode),
    /// The certificate of the key `key_name` expired.
    CertificateExpired { key_name: String },
    /// The authority asked for a renewal on a stream of the key `key_name`.
    RenewRequested { key_name: String },
    /// A config pushed on the streams.
    ConfigUpdate(PushedConfig),
}

/// A config pushed on the streams, with the messages to acknowledge once it is stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PushedConfig {
    pub(super) config: Value,
    /// The message that carried `config`, then those of the configs it superseded, by the stream each came on.
    ///
    /// INVARIANT: no config these messages carried has a higher revision than `config`, so that storing `config`
    /// leaves each of them stored or not newer, which the acknowledgement requires.
    pub(super) acks: Vec<(LinkId, String)>,
}

impl PushedConfig {
    /// Returns the config of the higher revision, or `self` for equal revisions, with the acknowledgements of both, at
    /// most [`MAX_CONFIG_ACKS`].
    fn merge(self, other: Self) -> Self {
        let (mut kept, superseded) = if config_revision(&self.config) < config_revision(&other.config) {
            (other, self)
        } else {
            (self, other)
        };
        let room = MAX_CONFIG_ACKS.saturating_sub(kept.acks.len());
        kept.acks.extend(superseded.acks.into_iter().take(room));
        kept
    }
}

/// The notices the identity hasn't handled yet, coalesced so that a flood of stream events doesn't grow them.
///
/// Each kind is kept once, or once per key for those naming a key, and only the pushed config with the highest
/// revision is kept, since storing it supersedes the others.
#[derive(Debug, Default)]
pub(super) struct Notices {
    terminal: Option<TerminalCode>,
    certificate_expired: BTreeSet<String>,
    renew_requested: BTreeSet<String>,
    lost: bool,
    stream_needed: bool,
    config_update: Option<PushedConfig>,
}

impl Notices {
    pub(super) fn push(&mut self, notice: Notice) {
        match notice {
            Notice::Lost => self.lost = true,
            Notice::StreamNeeded => self.stream_needed = true,
            Notice::Terminal(code) => self.terminal = Some(code),
            Notice::CertificateExpired { key_name } => {
                self.certificate_expired.insert(key_name);
            }
            Notice::RenewRequested { key_name } => {
                self.renew_requested.insert(key_name);
            }
            Notice::ConfigUpdate(pushed) => {
                self.config_update = Some(match self.config_update.take() {
                    Some(queued) => queued.merge(pushed),
                    None => pushed,
                });
            }
        }
    }

    pub(super) fn pop(&mut self) -> Option<Notice> {
        if let Some(code) = self.terminal.take() {
            return Some(Notice::Terminal(code));
        }
        if let Some(key_name) = self.certificate_expired.pop_first() {
            return Some(Notice::CertificateExpired { key_name });
        }
        if let Some(key_name) = self.renew_requested.pop_first() {
            return Some(Notice::RenewRequested { key_name });
        }
        if std::mem::take(&mut self.lost) {
            return Some(Notice::Lost);
        }
        if std::mem::take(&mut self.stream_needed) {
            return Some(Notice::StreamNeeded);
        }
        self.config_update.take().map(Notice::ConfigUpdate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinkId(u64);

/// The channel of one stream, as [`Links`] uses it.
pub(super) trait LinkChannel {
    fn ack(&self, correlation_id: &str);

    fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send;

    /// Returns a handle that queues device-management reports on the stream, if it can carry them.
    fn reporter(&self) -> Option<Reporter> {
        None
    }
}

impl LinkChannel for Channel {
    fn ack(&self, correlation_id: &str) {
        Channel::ack(self, correlation_id);
    }

    fn reporter(&self) -> Option<Reporter> {
        Some(Channel::reporter(self))
    }

    fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send {
        Channel::next_event(self)
    }
}

/// The task that owns the streams of one identity.
///
/// It handles their events while the runner is busy, even blocked on a state lock that another process holds, so that
/// a stream that must not reopen is dropped before its channel reopens it.
/// Dropping it closes every stream.
pub(super) struct Streams<C = Channel> {
    commands: mpsc::UnboundedSender<Command<C>>,
    inbox: Arc<Inbox>,
    status: watch::Receiver<Status>,
    task: JoinHandle<()>,
}

/// The notices the task hands to the runner.
#[derive(Default)]
struct Inbox {
    notices: Mutex<Notices>,
    /// Wakes the runner once notices arrive.
    arrived: Notify,
}

/// Starts a stream's channel.
type Connect<C> = Box<dyn FnOnce() -> anyhow::Result<C> + Send>;

enum Command<C> {
    Reconcile {
        want: Want,
        open: oneshot::Sender<bool>,
    },
    Open {
        url: Url,
        key_name: String,
        connect: Connect<C>,
    },
    Ack {
        link: LinkId,
        correlation_id: String,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Status {
    authenticated: bool,
    /// When the earliest opening of a stream starts or started.
    opening_at: Option<Instant>,
}

impl<C: LinkChannel + Send + 'static> Streams<C> {
    /// Starts the task of the identity `identity_id` with no device-management services.
    #[cfg(test)]
    pub(super) fn spawn(identity_id: Uuid) -> Self {
        Self::spawn_with(identity_id, Uuid::nil(), DeviceManagementContext::default())
    }

    /// Starts the task of the identity `identity_id` of the authority `authority_id`, whose links serve
    /// device-management requests through `device_management`; it must be called within a Tokio runtime.
    pub(super) fn spawn_with(
        identity_id: Uuid,
        authority_id: Uuid,
        device_management: DeviceManagementContext,
    ) -> Self {
        let (commands, command_receiver) = mpsc::unbounded_channel();
        let inbox = Arc::new(Inbox::default());
        let (status_sender, status) = watch::channel(Status::default());
        let task = tokio::spawn(run_streams(
            Links::with_device_management(identity_id, authority_id, device_management),
            command_receiver,
            Arc::clone(&inbox),
            status_sender,
        ));
        Self {
            commands,
            inbox,
            status,
            task,
        }
    }

    /// Returns whether the identity has an authenticated stream.
    pub(super) fn authenticated(&self) -> bool {
        self.status.borrow().authenticated
    }

    /// Returns whether a stream is opening at `now`, as [`Links::opening_at`] says.
    pub(super) fn opening(&self, now: Instant) -> bool {
        self.status.borrow().opening_at.is_some_and(|at| at <= now)
    }

    /// Applies `want` as [`Links::reconcile`] does, and returns whether [`Streams::open`] must open a stream for it.
    pub(super) async fn reconcile(&self, want: Want) -> bool {
        let (open, opened) = oneshot::channel();
        if self.commands.send(Command::Reconcile { want, open }).is_err() {
            return false;
        }
        opened.await.unwrap_or(false)
    }

    /// Opens a stream to `url` with the key `key_name` through `connect`, unless the streams no longer need one when
    /// the task handles the request, for example after a terminal closure.
    pub(super) fn open(
        &self,
        url: Url,
        key_name: String,
        connect: impl FnOnce() -> anyhow::Result<C> + Send + 'static,
    ) {
        let _ = self.commands.send(Command::Open {
            url,
            key_name,
            connect: Box::new(connect),
        });
    }

    /// Acknowledges the message `correlation_id` on the stream `link`, if it is still open.
    pub(super) fn ack(&self, link: LinkId, correlation_id: &str) {
        let _ = self.commands.send(Command::Ack {
            link,
            correlation_id: correlation_id.to_owned(),
        });
    }

    /// Waits until the streams report notices, which [`Streams::try_next_notice`] returns, or their status changes.
    pub(super) async fn wait(&mut self) {
        tokio::select! {
            () = self.inbox.arrived.notified() => {}
            Ok(()) = self.status.changed() => {}
        }
    }

    /// Returns the next notice if one is waiting.
    pub(super) fn try_next_notice(&mut self) -> Option<Notice> {
        self.inbox.notices.lock().pop()
    }
}

impl<C> Drop for Streams<C> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run_streams<C: LinkChannel>(
    mut links: Links<C>,
    mut commands: mpsc::UnboundedReceiver<Command<C>>,
    inbox: Arc<Inbox>,
    status: watch::Sender<Status>,
) {
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Reconcile { want, open }) => {
                    let _ = open.send(links.reconcile(want));
                }
                Some(Command::Open { url, key_name, connect }) => {
                    // The streams may no longer need this stream, for example after a terminal closure.
                    if links.needs_open() {
                        match connect() {
                            Ok(channel) => {
                                debug!(%url, %key_name, "Agent channel stream opening");
                                links.open(url, key_name, channel, Instant::now());
                            }
                            Err(error) => {
                                warn!(error = format!("{error:#}"), "Cannot open an agent channel stream");
                            }
                        }
                    }
                }
                Some(Command::Ack { link, correlation_id }) => links.ack(link, &correlation_id),
                None => return,
            },
            (link, event) = links.next_event() => links.handle(link, event, Instant::now()),
        }
        let mut arrived = false;
        while let Some(notice) = links.next_notice() {
            inbox.notices.lock().push(notice);
            arrived = true;
        }
        if arrived {
            inbox.arrived.notify_one();
        }
        let current = Status {
            authenticated: links.authenticated(),
            opening_at: links.opening_at(),
        };
        // Only a change wakes the runner, whose own commands would otherwise wake it again.
        status.send_if_modified(|status| std::mem::replace(status, current) != current);
    }
}

/// The streams of one identity.
///
/// A closed stream reopens only while [`Want`] asks for its URL and key and no stream replaces it.
/// Dropping a stream's channel is what stops it from reopening, so that a retired key never opens a stream, which the
/// authority would answer with the terminal `identity_unknown`.
pub(super) struct Links<C> {
    identity_id: Uuid,
    /// Stable across re-enrollment, unlike `identity_id`.
    authority_id: Uuid,
    device_management: DeviceManagementContext,
    workers_shutdown: watch::Sender<bool>,
    want: Want,
    /// The stream in use.
    active: Option<Link<C>>,
    /// The stream that replaces `active` once it authenticates ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract],
    /// step 6).
    ///
    /// INVARIANT: exists only while `active` is authenticated, so that an authenticated replacement always takes the
    /// place of a stream that was in use.
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
    replacement: Option<Link<C>>,
    /// Whether the authority ended the identity: a stream closed with a terminal outcome, so no stream opens again
    /// ([CONTRACT.agent-identity.md §5.4 "Errors"][errors]).
    ///
    /// [errors]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#54-errors
    ended: bool,
    /// Whether the authority asked for a stream to replace `active`.
    reconnect: bool,
    next_id: u64,
    notices: Notices,
}

struct Link<C> {
    id: LinkId,
    channel: C,
    url: Url,
    key_name: String,
    state: LinkState,
    warned_malformed_operation_id: bool,
    #[cfg(windows)]
    journal_full_warned: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkState {
    /// The stream opens from `at` until it authenticates or closes; after a closure, `at` is when it opens again.
    Opening {
        at: Instant,
    },
    Authenticated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Active,
    Replacement,
}

impl<C: LinkChannel> Links<C> {
    #[cfg(test)]
    pub(super) fn new(identity_id: Uuid) -> Self {
        Self::with_device_management(identity_id, Uuid::nil(), DeviceManagementContext::default())
    }

    pub(super) fn with_device_management(
        identity_id: Uuid,
        authority_id: Uuid,
        device_management: DeviceManagementContext,
    ) -> Self {
        Self {
            identity_id,
            authority_id,
            device_management,
            workers_shutdown: watch::channel(false).0,
            want: Want::Nothing,
            active: None,
            replacement: None,
            ended: false,
            reconnect: false,
            next_id: 0,
            notices: Notices::default(),
        }
    }

    /// Returns whether the identity has an authenticated stream.
    pub(super) fn authenticated(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| active.state == LinkState::Authenticated)
    }

    /// Returns when the earliest opening of a stream starts or started: from then, the stream has sent or may send its
    /// opening request, until it authenticates or closes.
    pub(super) fn opening_at(&self) -> Option<Instant> {
        [&self.active, &self.replacement]
            .into_iter()
            .flatten()
            .filter_map(|link| match link.state {
                LinkState::Opening { at } => Some(at),
                LinkState::Authenticated => None,
            })
            .min()
    }

    /// Drops the streams `want` doesn't allow, and returns whether [`Links::open`] must open a stream for it.
    ///
    /// Once the authority ended the identity, nothing is wanted.
    pub(super) fn reconcile(&mut self, want: Want) -> bool {
        self.want = if self.ended { Want::Nothing } else { want };
        if !matches!(self.want, Want::Stream { .. }) {
            self.replacement = None;
            if self.want == Want::Nothing || !self.authenticated() {
                self.active = None;
                self.reconnect = false;
            }
            return false;
        }
        if self
            .replacement
            .as_ref()
            .is_some_and(|replacement| !self.serves(replacement))
        {
            self.replacement = None;
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.state != LinkState::Authenticated && !self.serves(active))
        {
            self.active = None;
        }
        self.needs_open()
    }

    /// Returns whether [`Links::open`] must open a stream for what the identity wants: none is in use or opening for
    /// it, or the authority asked to replace the stream in use.
    fn needs_open(&self) -> bool {
        if !matches!(self.want, Want::Stream { .. }) {
            return false;
        }
        match &self.active {
            None => true,
            Some(active) if active.state != LinkState::Authenticated => !self.serves(active),
            Some(active) => match &self.replacement {
                Some(replacement) => !self.serves(replacement),
                None => self.reconnect || !self.serves(active),
            },
        }
    }

    fn serves(&self, link: &Link<C>) -> bool {
        matches!(&self.want, Want::Stream { url, key_name } if link.url == *url && link.key_name == *key_name)
    }

    /// Adds the stream that `channel` opens since `now` to `url` with the key `key_name`.
    ///
    /// It replaces an authenticated stream once it authenticates itself.
    pub(super) fn open(&mut self, url: Url, key_name: String, channel: C, now: Instant) -> LinkId {
        let id = LinkId(self.next_id);
        self.next_id += 1;
        let link = Link {
            id,
            channel,
            url,
            key_name,
            state: LinkState::Opening { at: now },
            warned_malformed_operation_id: false,
            #[cfg(windows)]
            journal_full_warned: Arc::new(AtomicBool::new(false)),
        };
        if self.authenticated() {
            self.replacement = Some(link);
        } else {
            self.active = Some(link);
        }
        id
    }

    /// Acknowledges the message `correlation_id` on the stream `link`, if it is still open.
    pub(super) fn ack(&self, link: LinkId, correlation_id: &str) {
        if let Some(link) = [&self.active, &self.replacement]
            .into_iter()
            .flatten()
            .find(|candidate| candidate.id == link)
        {
            link.channel.ack(correlation_id);
        }
    }

    /// Returns a notice the identity hasn't received.
    pub(super) fn next_notice(&mut self) -> Option<Notice> {
        self.notices.pop()
    }

    /// Waits for the next event of a stream; `None` means that the stream's channel has stopped.
    pub(super) async fn next_event(&mut self) -> (LinkId, Option<Event>) {
        tokio::select! {
            event = next_link_event(self.active.as_mut()) => event,
            event = next_link_event(self.replacement.as_mut()) => event,
        }
    }

    /// Updates the streams for `event` of the stream `link` at `now`, and records what the identity must do as
    /// notices.
    pub(super) fn handle(&mut self, link: LinkId, event: Option<Event>, now: Instant) {
        let role = match (&self.active, &self.replacement) {
            (Some(active), _) if active.id == link => Role::Active,
            (_, Some(replacement)) if replacement.id == link => Role::Replacement,
            _ => return,
        };
        let was_authenticated = self.authenticated();
        match event {
            None => {
                warn!("Agent channel stopped unexpectedly");
                self.remove(role);
            }
            Some(Event::Authenticated) => {
                if role == Role::Replacement {
                    // `CONTRACT.agent-identity.md` §7.3 step 6: the new stream is open, so the old one closes.
                    self.active = self.replacement.take();
                    self.reconnect = false;
                }
                if let Some(active) = &mut self.active {
                    active.state = LinkState::Authenticated;
                    active.warned_malformed_operation_id = false;
                    #[cfg(windows)]
                    active.journal_full_warned.store(false, Ordering::Relaxed);
                    info!(url = %active.url, "Agent channel authenticated");
                }
            }
            Some(Event::RenewRequested { id, reason }) => {
                info!(%reason, "Agent channel requested a renewal");
                if let Some(link) = self.link(role) {
                    link.channel.ack(&id);
                    let key_name = link.key_name.clone();
                    self.notices.push(Notice::RenewRequested { key_name });
                }
            }
            Some(Event::Reconnect { reason, .. }) => {
                info!(%reason, "Agent channel requested a new stream");
                if role == Role::Active && matches!(self.want, Want::Stream { .. }) {
                    self.reconnect = true;
                }
            }
            Some(Event::ConfigUpdate { id, config_json }) => match client::parse_pushed_config(&config_json) {
                Ok(config) => self.notices.push(Notice::ConfigUpdate(PushedConfig {
                    config,
                    acks: vec![(link, id)],
                })),
                // `CONTRACT.agent-identity.md` §5.2: a config with another version is a transient failure, and the
                // stored config stays; the authority sends it again after the next `Hello`.
                Err(error) => warn!(%error, "Ignoring an Agent Identity config pushed on the agent channel"),
            },
            // UNTESTED: A real Authority stream must keep reporting while journal I/O stalls.
            // The saturation test uses fake channel events; exercise an authenticated stream when changing this dispatch.
            Some(Event::DeviceManagement { id, request }) => {
                if crate::device_management::has_unrecorded_malformed_operation_id(&self.device_management, &request) {
                    if let Some(link) = self.link_mut(role)
                        && !std::mem::replace(&mut link.warned_malformed_operation_id, true)
                    {
                        warn!("Ignoring package operation with malformed operation ID");
                    }
                } else if let Some(link) = self.link(role)
                    && let Some(reporter) = link.channel.reporter()
                {
                    let channel_reporter = crate::device_management::ChannelReporter {
                        reporter,
                        #[cfg(windows)]
                        journal_full_warned: Arc::clone(&link.journal_full_warned),
                    };
                    crate::device_management::handle(
                        self.device_management.clone(),
                        self.identity_id,
                        self.authority_id,
                        id,
                        request,
                        channel_reporter,
                        self.workers_shutdown.subscribe(),
                    );
                }
            }
            Some(Event::Closed { closure, reopen_after }) => self.closed(role, closure, reopen_after, now),
        }
        if was_authenticated && !self.authenticated() {
            self.notices.push(Notice::Lost);
        }
        if self.needs_open() {
            self.notices.push(Notice::StreamNeeded);
        }
    }

    fn closed(&mut self, role: Role, closure: Closure, reopen_after: Option<Duration>, now: Instant) {
        let superseded = role == Role::Active && self.replacement.is_some();
        let Some(link) = self.link(role) else {
            return;
        };
        let was_authenticated = link.state == LinkState::Authenticated;
        let key_name = link.key_name.clone();
        // A stream reopens only while it serves what the identity wants and nothing replaces it.
        let reopen_after = reopen_after.filter(|_| !superseded && self.serves(link));
        match closure.class {
            ClosureClass::Terminal(code) => self.notices.push(Notice::Terminal(code)),
            ClosureClass::CertificateExpired => self.notices.push(Notice::CertificateExpired { key_name }),
            ClosureClass::Transient(_) => {}
        }
        if was_authenticated {
            warn!(
                grpc_code = ?closure.grpc_code,
                error_code = closure.error_code.as_ref().map(ErrorCode::as_str),
                reason = %closure.reason,
                ?reopen_after,
                "Agent channel stream closed"
            );
            self.reconnect = false;
        } else {
            debug!(
                grpc_code = ?closure.grpc_code,
                error_code = closure.error_code.as_ref().map(ErrorCode::as_str),
                reason = %closure.reason,
                ?reopen_after,
                "Agent channel stream did not open"
            );
        }
        match (reopen_after, self.link_mut(role)) {
            (Some(delay), Some(link)) => link.state = LinkState::Opening { at: now + delay },
            _ => self.remove(role),
        }
        if let ClosureClass::Terminal(_) = closure.class {
            // `CONTRACT.agent-identity.md` §5.4: the identity is over, so every other stream closes too, and none opens
            // again.
            self.ended = true;
            self.reconcile(Want::Nothing);
        }
    }

    fn link(&self, role: Role) -> Option<&Link<C>> {
        match role {
            Role::Active => self.active.as_ref(),
            Role::Replacement => self.replacement.as_ref(),
        }
    }

    fn link_mut(&mut self, role: Role) -> Option<&mut Link<C>> {
        match role {
            Role::Active => self.active.as_mut(),
            Role::Replacement => self.replacement.as_mut(),
        }
    }

    /// Drops the stream of `role`; the replacement takes the place of a dropped active stream.
    fn remove(&mut self, role: Role) {
        match role {
            Role::Active => {
                self.active = self.replacement.take();
                self.reconnect = false;
            }
            Role::Replacement => self.replacement = None,
        }
    }
}

impl<C> Drop for Links<C> {
    fn drop(&mut self) {
        self.workers_shutdown.send_replace(true);
    }
}

async fn next_link_event<C: LinkChannel>(link: Option<&mut Link<C>>) -> (LinkId, Option<Event>) {
    match link {
        Some(link) => (link.id, link.channel.next_event().await),
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use agent_channel_client::TransientKind;
    use rstest::rstest;
    use tracing::{Metadata, Subscriber, span};

    use super::*;

    struct Warnings(Arc<AtomicUsize>, &'static str);

    struct MessageContains {
        needle: &'static str,
        matched: bool,
    }

    impl tracing::field::Visit for MessageContains {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" && format!("{value:?}").contains(self.needle) {
                self.matched = true;
            }
        }
    }

    impl Subscriber for Warnings {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::WARN
        }

        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut message = MessageContains {
                needle: self.1,
                matched: false,
            };
            event.record(&mut message);
            if message.matched {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn enter(&self, _: &span::Id) {}

        fn exit(&self, _: &span::Id) {}
    }

    /// A channel whose events the test sends; it records whether it was dropped.
    struct TestChannel {
        events: mpsc::UnboundedReceiver<Event>,
        dropped: Arc<AtomicBool>,
    }

    impl LinkChannel for TestChannel {
        fn ack(&self, _correlation_id: &str) {}

        fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send {
            self.events.recv()
        }
    }

    impl Drop for TestChannel {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    /// Returns a channel, the sender of its events, and the flag it sets once dropped.
    fn test_channel() -> (TestChannel, mpsc::UnboundedSender<Event>, Arc<AtomicBool>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let channel = TestChannel {
            events: receiver,
            dropped: Arc::clone(&dropped),
        };
        (channel, events, dropped)
    }

    #[cfg(windows)]
    struct BoundedTestChannel {
        events: mpsc::Receiver<Event>,
        acknowledgements: mpsc::UnboundedSender<String>,
        reporter: Reporter,
        dropped: Arc<AtomicBool>,
    }

    #[cfg(windows)]
    impl LinkChannel for BoundedTestChannel {
        fn ack(&self, correlation_id: &str) {
            let _ = self.acknowledgements.send(correlation_id.to_owned());
        }

        fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send {
            self.events.recv()
        }

        fn reporter(&self) -> Option<Reporter> {
            Some(self.reporter.clone())
        }
    }

    #[cfg(windows)]
    impl Drop for BoundedTestChannel {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    /// The system temporary directory can be writable by other accounts, which fails the journal's check of the
    /// directories above, so tests use the user's local application data directory where there is one.
    #[cfg(windows)]
    fn test_tempdir(prefix: &str) -> std::io::Result<tempfile::TempDir> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        tempfile::Builder::new().prefix(prefix).tempdir_in(base)
    }

    #[cfg(windows)]
    fn bounded_test_channel(
        reporter: Reporter,
    ) -> (
        BoundedTestChannel,
        mpsc::Sender<Event>,
        mpsc::UnboundedReceiver<String>,
        Arc<AtomicBool>,
    ) {
        let (events, receiver) = mpsc::channel(16);
        let (acknowledgements, acks) = mpsc::unbounded_channel();
        let dropped = Arc::new(AtomicBool::new(false));
        (
            BoundedTestChannel {
                events: receiver,
                acknowledgements,
                reporter,
                dropped: Arc::clone(&dropped),
            },
            events,
            acks,
            dropped,
        )
    }

    fn url() -> Url {
        Url::parse("https://authority.test/dvls").expect("valid test URL")
    }

    fn stream(key_name: &str) -> Want {
        Want::Stream {
            url: url(),
            key_name: key_name.to_owned(),
        }
    }

    /// Opens a stream with the key `key_name`, and returns it with the flag its channel sets once dropped.
    fn open(links: &mut Links<TestChannel>, key_name: &str, now: Instant) -> (LinkId, Arc<AtomicBool>) {
        let (channel, _events, dropped) = test_channel();
        let link = links.open(url(), key_name.to_owned(), channel, now);
        (link, dropped)
    }

    fn closed(class: ClosureClass, reopen_after: Option<Duration>) -> Event {
        Event::Closed {
            closure: Closure {
                class,
                grpc_code: None,
                error_code: None,
                server_time: None,
                reason: "closed by the test".to_owned(),
            },
            reopen_after,
        }
    }

    fn closed_transiently(reopen_after: Duration) -> Option<Event> {
        Some(closed(
            ClosureClass::Transient(TransientKind::Outage),
            Some(reopen_after),
        ))
    }

    fn notices(links: &mut Links<TestChannel>) -> Vec<Notice> {
        std::iter::from_fn(|| links.next_notice()).collect()
    }

    /// Opens a stream through `streams`, as the runner does, and returns the sender of its events and the flag its
    /// channel sets once dropped.
    fn open_stream(streams: &Streams<TestChannel>, key_name: &str) -> (mpsc::UnboundedSender<Event>, Arc<AtomicBool>) {
        let (channel, events, dropped) = test_channel();
        streams.open(url(), key_name.to_owned(), move || Ok(channel));
        (events, dropped)
    }

    /// Waits until the streams report an authenticated stream.
    async fn wait_until_authenticated<C: LinkChannel + Send + 'static>(streams: &mut Streams<C>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !streams.authenticated() {
                streams.wait().await;
            }
        })
        .await
        .expect("no stream authenticated in time");
    }

    /// Waits for a terminal notice, which the test, unlike a runner, doesn't act on.
    async fn wait_for_terminal<C: LinkChannel + Send + 'static>(streams: &mut Streams<C>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if std::iter::from_fn(|| streams.try_next_notice()).any(|notice| matches!(notice, Notice::Terminal(_)))
                {
                    return;
                }
                streams.wait().await;
            }
        })
        .await
        .expect("no terminal notice in time");
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // After a terminal outcome, the agent never reconnects for the identity.
    // The runner learns of the outcome from a notice only once it isn't busy, so the streams' task holds this rule.
    #[tokio::test]
    async fn after_a_terminal_closure_no_stream_opens_even_before_the_runner_acts_on_it() -> anyhow::Result<()> {
        let mut streams = Streams::spawn(Uuid::nil());
        assert!(streams.reconcile(stream("current")).await);
        let (events, _dropped) = open_stream(&streams, "current");
        events.send(Event::Authenticated)?;
        wait_until_authenticated(&mut streams).await;
        events.send(closed(ClosureClass::Terminal(TerminalCode::IdentityRevoked), None))?;
        wait_for_terminal(&mut streams).await;

        let wants_stream = streams.reconcile(stream("current")).await;
        let connected = Arc::new(AtomicBool::new(false));
        let connecting = Arc::clone(&connected);
        streams.open(url(), "current".to_owned(), move || {
            connecting.store(true, Ordering::SeqCst);
            Ok(test_channel().0)
        });
        // The task handles commands in order, so this reply follows the handling of the open.
        streams.reconcile(stream("current")).await;

        assert!(!wants_stream);
        assert!(!connected.load(Ordering::SeqCst));
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // A terminal outcome ends the identity, so the stream in use closes too.
    #[tokio::test]
    async fn a_terminal_refusal_of_a_new_stream_closes_the_stream_in_use_before_the_runner_acts_on_it()
    -> anyhow::Result<()> {
        let mut streams = Streams::spawn(Uuid::nil());
        assert!(streams.reconcile(stream("current")).await);
        let (current_events, current_dropped) = open_stream(&streams, "current");
        current_events.send(Event::Authenticated)?;
        wait_until_authenticated(&mut streams).await;
        assert!(streams.reconcile(stream("renewed")).await);
        let (renewed_events, _renewed_dropped) = open_stream(&streams, "renewed");

        renewed_events.send(closed(ClosureClass::Terminal(TerminalCode::IdentityUnknown), None))?;
        wait_for_terminal(&mut streams).await;

        assert!(current_dropped.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn a_burst_of_config_updates_while_the_runner_is_busy_leaves_one_with_the_highest_revision()
    -> anyhow::Result<()> {
        let mut streams = Streams::spawn(Uuid::nil());
        assert!(streams.reconcile(stream("current")).await);
        let (events, _dropped) = open_stream(&streams, "current");
        events.send(Event::Authenticated)?;
        wait_until_authenticated(&mut streams).await;

        for revision in [3, 5, 2, 4] {
            events.send(config_update(revision))?;
        }
        // The task handles a stream's events in order, so the loss follows every config.
        events.send(closed(
            ClosureClass::Transient(TransientKind::Outage),
            Some(Duration::from_secs(60)),
        ))?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while streams.authenticated() {
                streams.wait().await;
            }
        })
        .await?;

        let pushed: Vec<_> = std::iter::from_fn(|| streams.try_next_notice())
            .filter_map(|notice| match notice {
                Notice::ConfigUpdate(pushed) => Some(pushed),
                _ => None,
            })
            .collect();
        // oracle: intent devolutions-agent/src/identity/INTENT.md §Channel
        let [pushed] = pushed.as_slice() else {
            panic!("expected one queued config, got {pushed:?}");
        };
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        // Step 7: the agent stores a pushed config if its revision is higher and acknowledges every `ConfigUpdate`, so
        // the highest revision ends stored and each message is acknowledged once it is.
        assert_eq!(pushed.config, serde_json::json!({ "version": 1, "revision": 5 }));
        let mut acknowledged: Vec<&str> = pushed.acks.iter().map(|(_, id)| id.as_str()).collect();
        acknowledged.sort_unstable();
        assert_eq!(acknowledged, ["update-2", "update-3", "update-4", "update-5"]);
        Ok(())
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn malformed_operation_ids_are_ignored_and_warned_once_per_connection() {
        use agent_channel_proto::device_management_request::Request;
        use agent_channel_proto::{DeviceManagementRequest, PackageOperationRequest};

        struct ProbeChannel(Arc<AtomicUsize>);

        impl LinkChannel for ProbeChannel {
            fn ack(&self, _: &str) {}

            fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send {
                std::future::pending()
            }

            fn reporter(&self) -> Option<Reporter> {
                self.0.fetch_add(1, Ordering::SeqCst);
                None
            }
        }

        let warnings = Arc::new(AtomicUsize::new(0));
        let _subscriber = tracing::subscriber::set_default(Warnings(
            Arc::clone(&warnings),
            "Ignoring package operation with malformed operation ID",
        ));
        let reporter_requests = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        #[cfg(windows)]
        let (_root, context) = {
            let root = test_tempdir("channel-validation-").expect("test directory is created");
            let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
            let legacy = PackageOperationRequest {
                operation_id: "legacy-id".to_owned(),
                ..Default::default()
            };
            let (context, _entered, _resume) = DeviceManagementContext::default()
                .with_recorded_operation_for_test(data, &legacy)
                .expect("test journal opens");
            (root, context)
        };
        #[cfg(not(windows))]
        let context = DeviceManagementContext::default();
        let mut links = Links::with_device_management(Uuid::nil(), Uuid::nil(), context);
        links.reconcile(stream("current"));
        let link = links.open(
            url(),
            "current".to_owned(),
            ProbeChannel(Arc::clone(&reporter_requests)),
            now,
        );
        links.handle(link, Some(Event::Authenticated), now);
        let operation = |operation_id: String| {
            Some(Event::DeviceManagement {
                id: Uuid::new_v4().to_string(),
                request: DeviceManagementRequest {
                    request: Some(Request::PackageOperation(PackageOperationRequest {
                        operation_id,
                        ..Default::default()
                    })),
                },
            })
        };

        for invalid in [
            "a".repeat(65_485),
            String::new(),
            "abcdef012345-6789-0123-456789abcdef".to_owned(),
            "abcdef01-2345-6789-0123-456789abcdeg".to_owned(),
            "ABCDEF01-2345-6789-ABCD-EF0123456789".to_owned(),
        ] {
            links.handle(link, operation(invalid), now);
        }
        assert_eq!(reporter_requests.load(Ordering::SeqCst), 0);
        assert_eq!(warnings.load(Ordering::SeqCst), 1);

        #[cfg(windows)]
        {
            links.handle(link, operation("legacy-id".to_owned()), now);
            assert_eq!(reporter_requests.load(Ordering::SeqCst), 1);
        }
        let recorded_requests = reporter_requests.load(Ordering::SeqCst);
        for valid in [
            "abcdef01-2345-6789-abcd-ef0123456789",
            "01234567-0123-4567-8901-234567890123",
            "00000000-0000-0000-0000-000000000000",
            "550e8400-e29b-11d4-a716-446655440000",
        ] {
            links.handle(link, operation(valid.to_owned()), now);
        }
        assert_eq!(reporter_requests.load(Ordering::SeqCst), recorded_requests + 4);

        links.handle(link, closed_transiently(Duration::from_secs(1)), now);
        let before_reconnect = warnings.load(Ordering::SeqCst);
        links.handle(link, Some(Event::Authenticated), now + Duration::from_secs(1));
        links.handle(link, operation("not-a-uuid".to_owned()), now);
        assert_eq!(reporter_requests.load(Ordering::SeqCst), recorded_requests + 4);
        assert_eq!(warnings.load(Ordering::SeqCst), before_reconnect + 1);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[cfg(windows)]
    #[tokio::test]
    async fn a_full_journal_warns_once_per_connection() -> anyhow::Result<()> {
        use agent_channel_client::{ChannelClient, HelloFields, Settings, Target};
        use agent_channel_proto::device_management_request::Request;
        use agent_channel_proto::{DeviceManagementRequest, PackageOperationRequest};

        let root = test_tempdir("channel-full-")?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let context = DeviceManagementContext::default().with_full_journal_for_test(data)?;
        let key = device_key::generate(
            &device_key::KeyBackend::File { dir: data.join("keys") },
            &device_key::new_key_name("test"),
        )?;
        let client = ChannelClient::new(http_client_proxy::ProxyConfig::Off, &[], Settings::default())?;
        let report_channel = client.connect(Target {
            url: Url::parse("https://127.0.0.1:1")?,
            key: Arc::from(key),
            leaf_certificate_der: Vec::new(),
            hello: Arc::new(|| HelloFields {
                metadata: Default::default(),
                config_revision: 0,
                capabilities: Vec::new(),
            }),
        })?;
        let (channel, _events, _acks, _dropped) = bounded_test_channel(report_channel.reporter());
        let mut links = Links::with_device_management(Uuid::nil(), Uuid::nil(), context);
        let now = Instant::now();
        links.reconcile(stream("current"));
        let link = links.open(url(), "current".to_owned(), channel, now);
        let warnings = Arc::new(AtomicUsize::new(0));
        let _subscriber =
            tracing::subscriber::set_default(Warnings(Arc::clone(&warnings), "Package operation journal is full"));
        links.handle(link, Some(Event::Authenticated), now);
        let operation = || {
            Some(Event::DeviceManagement {
                id: Uuid::new_v4().to_string(),
                request: DeviceManagementRequest {
                    request: Some(Request::PackageOperation(PackageOperationRequest {
                        operation_id: Uuid::new_v4().to_string(),
                        ..Default::default()
                    })),
                },
            })
        };
        for _ in 0..3 {
            links.handle(link, operation(), now);
        }
        assert_eq!(warnings.load(Ordering::SeqCst), 1);

        links.handle(link, closed_transiently(Duration::from_secs(1)), now);
        links.handle(link, Some(Event::Authenticated), now + Duration::from_secs(1));
        links.handle(link, operation(), now);
        assert_eq!(warnings.load(Ordering::SeqCst), 2);
        Ok(())
    }

    // oracle: intent devolutions-agent/src/device_management/INTENT.md §device-management-remote-operations
    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    #[cfg(windows)]
    #[tokio::test]
    async fn saturated_journal_keeps_channel_traffic_reconnect_and_shutdown_live() -> anyhow::Result<()> {
        use agent_channel_client::{ChannelClient, HelloFields, Settings, Target};
        use agent_channel_proto::device_management_request::Request;
        use agent_channel_proto::{DeviceManagementRequest, PackageOperationRequest};

        let root = test_tempdir("channel-overload-")?;
        let data = camino::Utf8Path::from_path(root.path()).expect("test path is UTF-8");
        let operation = PackageOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let (context, entered, resume) = DeviceManagementContext::default()
            .with_remote_features(true, false)
            .with_recorded_operation_for_test(data, &operation)?;
        let blocked = PackageOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let new = PackageOperationRequest {
            operation_id: Uuid::new_v4().to_string(),
            ..Default::default()
        };

        let key = device_key::generate(
            &device_key::KeyBackend::File { dir: data.join("keys") },
            &device_key::new_key_name("test"),
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        let client = ChannelClient::new(http_client_proxy::ProxyConfig::Off, &[], Settings::default())?;
        let report_channel = client.connect(Target {
            url: Url::parse(&format!("https://{address}"))?,
            key: Arc::from(key),
            leaf_certificate_der: Vec::new(),
            hello: Arc::new(|| HelloFields {
                metadata: Default::default(),
                config_revision: 0,
                capabilities: Vec::new(),
            }),
        })?;

        let mut streams = Streams::spawn_with(Uuid::nil(), Uuid::nil(), context.clone());
        assert!(streams.reconcile(stream("current")).await);
        let (channel, events, mut acks, first_dropped) = bounded_test_channel(report_channel.reporter());
        streams.open(url(), "current".to_owned(), move || Ok(channel));
        events.send(Event::Authenticated).await?;
        wait_until_authenticated(&mut streams).await;
        events
            .send(Event::DeviceManagement {
                id: Uuid::new_v4().to_string(),
                request: DeviceManagementRequest {
                    request: Some(Request::PackageOperation(blocked.clone())),
                },
            })
            .await?;
        tokio::time::timeout(
            Duration::from_secs(12),
            tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(10))),
        )
        .await???;

        tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..64 {
                events
                    .send(Event::DeviceManagement {
                        id: Uuid::new_v4().to_string(),
                        request: DeviceManagementRequest {
                            request: Some(Request::PackageOperation(operation.clone())),
                        },
                    })
                    .await?;
            }
            events.send(config_update(4)).await?;
            events
                .send(Event::RenewRequested {
                    id: "renewal".to_owned(),
                    reason: "test".to_owned(),
                })
                .await?;
            events
                .send(Event::Reconnect {
                    id: "reconnect".to_owned(),
                    reason: "test".to_owned(),
                })
                .await?;
            Ok::<(), mpsc::error::SendError<Event>>(())
        })
        .await??;

        let busy = tokio::time::timeout(Duration::from_secs(10), context.submit_operation_for_test(new)).await?;
        assert_eq!(busy.error, "agent busy: nothing was started");

        let mut saw_config = false;
        let mut saw_renewal = false;
        let mut saw_reconnect = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !(saw_config && saw_renewal && saw_reconnect) {
                while let Some(notice) = streams.try_next_notice() {
                    match notice {
                        Notice::ConfigUpdate(pushed) => saw_config = pushed.config["revision"] == 4,
                        Notice::RenewRequested { .. } => saw_renewal = true,
                        Notice::StreamNeeded => saw_reconnect = true,
                        _ => {}
                    }
                }
                if !(saw_config && saw_renewal && saw_reconnect) {
                    streams.wait().await;
                }
            }
        })
        .await?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), acks.recv()).await?,
            Some("renewal".to_owned())
        );
        assert!(streams.reconcile(stream("current")).await);
        let (replacement, replacement_events, _acks, replacement_dropped) =
            bounded_test_channel(report_channel.reporter());
        streams.open(url(), "current".to_owned(), move || Ok(replacement));
        replacement_events.send(Event::Authenticated).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !first_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        replacement_events
            .send(closed(ClosureClass::Terminal(TerminalCode::IdentityRevoked), None))
            .await?;
        wait_for_terminal(&mut streams).await;
        assert!(replacement_dropped.load(Ordering::SeqCst));
        assert!(!streams.reconcile(stream("current")).await);

        let mut stopping = Streams::spawn_with(Uuid::nil(), Uuid::nil(), context.clone());
        assert!(stopping.reconcile(stream("current")).await);
        let (channel, events, mut acks, dropped) = bounded_test_channel(report_channel.reporter());
        stopping.open(url(), "current".to_owned(), move || Ok(channel));
        events.send(Event::Authenticated).await?;
        wait_until_authenticated(&mut stopping).await;
        events
            .send(Event::DeviceManagement {
                id: Uuid::new_v4().to_string(),
                request: DeviceManagementRequest {
                    request: Some(Request::PackageOperation(operation.clone())),
                },
            })
            .await?;
        events
            .send(Event::RenewRequested {
                id: "before-shutdown".to_owned(),
                reason: "test".to_owned(),
            })
            .await?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), acks.recv()).await?,
            Some("before-shutdown".to_owned())
        );
        drop(stopping);
        tokio::time::timeout(Duration::from_secs(10), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        resume.send(())?;
        let blocked = tokio::time::timeout(Duration::from_secs(10), context.submit_operation_for_test(blocked)).await?;
        assert_eq!(blocked.error, "remote package writes are disabled");
        assert!(
            tokio::time::timeout(Duration::from_secs(10), context.submit_operation_for_test(operation))
                .await?
                .success
        );
        Ok(())
    }

    fn config_update(revision: u64) -> Event {
        Event::ConfigUpdate {
            id: format!("update-{revision}"),
            config_json: serde_json::json!({ "version": 1, "revision": revision }).to_string(),
        }
    }

    #[test]
    fn a_flood_of_pushed_configs_keeps_the_highest_and_a_bounded_number_of_acknowledgements() {
        // oracle: intent devolutions-agent/src/identity/INTENT.md §Channel
        let now = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (link, _dropped) = open(&mut links, "current", now);
        links.handle(link, Some(Event::Authenticated), now);

        for revision in 1..=100 {
            links.handle(link, Some(config_update(revision)), now);
        }

        let queued = notices(&mut links);
        let [Notice::ConfigUpdate(pushed)] = queued.as_slice() else {
            panic!("expected one queued config");
        };
        assert_eq!(pushed.config, serde_json::json!({ "version": 1, "revision": 100 }));
        assert!(pushed.acks.contains(&(link, "update-100".to_owned())));
        // The highest config's own acknowledgement and at most 32 of the configs it superseded.
        assert!(pushed.acks.len() <= 1 + 32);
    }

    #[test]
    fn repeated_renewal_requests_and_stream_needs_leave_one_notice_each() {
        // oracle: mutant every renewal request and stream need stays queued until the runner takes it
        let now = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (link, _dropped) = open(&mut links, "current", now);
        links.handle(link, Some(Event::Authenticated), now);
        let reconnect = Event::Reconnect {
            id: "reconnect".to_owned(),
            reason: "maintenance".to_owned(),
        };
        links.handle(link, Some(reconnect), now);

        for _ in 0..3 {
            let renewal = Event::RenewRequested {
                id: "renewal".to_owned(),
                reason: "admin".to_owned(),
            };
            links.handle(link, Some(renewal), now);
        }

        assert_eq!(
            notices(&mut links),
            [
                Notice::RenewRequested {
                    key_name: "current".to_owned()
                },
                Notice::StreamNeeded
            ]
        );
    }

    // A stream that reopens with a retired key draws the terminal `identity_unknown` (step 4 of the signature checks),
    // and no stream opens while the outcome of a `confirm` may be unknown (step 3 of agent renewal), so a stream that
    // closes in either state must be dropped before its channel reopens it.
    #[rstest]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §signatures
    #[case::its_key_was_replaced(stream("renewed"))]
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    #[case::the_streams_are_held(Want::Hold)]
    fn an_authenticated_stream_that_may_not_reopen_is_dropped_when_it_closes(#[case] want: Want) {
        let now = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (link, dropped) = open(&mut links, "current", now);
        links.handle(link, Some(Event::Authenticated), now);
        links.reconcile(want);

        links.handle(link, closed_transiently(Duration::from_secs(1)), now);

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_reconnect_request_wakes_the_runner_and_the_old_stream_closes_once_the_new_one_authenticates() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
        // On `Reconnect` (step 6), the agent opens the new stream, then closes the old one; only the runner can open a
        // stream, so the request reaches it as a notice.
        let now = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (first, first_dropped) = open(&mut links, "current", now);
        links.handle(first, Some(Event::Authenticated), now);

        links.handle(
            first,
            Some(Event::Reconnect {
                id: "reconnect".to_owned(),
                reason: "maintenance".to_owned(),
            }),
            now,
        );
        assert_eq!(notices(&mut links), [Notice::StreamNeeded]);
        assert!(links.reconcile(stream("current")));
        let (second, second_dropped) = open(&mut links, "current", now);
        assert!(!first_dropped.load(Ordering::SeqCst));

        links.handle(second, Some(Event::Authenticated), now);
        assert!(first_dropped.load(Ordering::SeqCst));
        assert!(!second_dropped.load(Ordering::SeqCst));
        assert!(links.authenticated());
        assert_eq!(notices(&mut links), []);
    }

    #[test]
    fn holding_drops_a_stream_that_has_not_authenticated() {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
        // Once `confirm` is sent (step 3), no stream may be opening.
        let now = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (_link, dropped) = open(&mut links, "current", now);

        links.reconcile(Want::Hold);

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_wanted_stream_that_closes_reopens_and_reports_the_loss() {
        // oracle: intent crates/agent-identity/INTENT.md §Schedules
        // Check-in resumes once no stream has authenticated for 1 h, so the runner learns when the identity's last
        // authenticated stream closes.
        let now = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (link, dropped) = open(&mut links, "current", now);
        links.handle(link, Some(Event::Authenticated), now);

        links.handle(link, closed_transiently(Duration::from_secs(1)), now);

        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(!links.authenticated());
        assert_eq!(notices(&mut links), [Notice::Lost]);
    }

    #[test]
    fn a_stream_is_opening_until_it_authenticates_and_again_once_its_reopening_starts() {
        // oracle: mutant a stream waiting to reopen counts as opening during its backoff
        // The runner sends `confirm` only while no stream is opening (`CONTRACT.agent-identity.md` §8.1 step 3), and a
        // stream waiting to reopen sends nothing until its backoff ends.
        let opened_at = Instant::now();
        let mut links = Links::new(Uuid::nil());
        links.reconcile(stream("current"));
        let (link, _dropped) = open(&mut links, "current", opened_at);
        assert_eq!(links.opening_at(), Some(opened_at));

        let closed_at = opened_at + Duration::from_secs(2);
        links.handle(link, closed_transiently(Duration::from_secs(5)), closed_at);
        assert_eq!(links.opening_at(), Some(closed_at + Duration::from_secs(5)));

        links.handle(link, Some(Event::Authenticated), closed_at + Duration::from_secs(6));
        assert_eq!(links.opening_at(), None);
    }

    #[test]
    fn dropping_links_cancels_their_device_management_workers() {
        // oracle: regression #2194
        let links = Links::<TestChannel>::new(Uuid::nil());
        let workers_shutdown = links.workers_shutdown.subscribe();

        drop(links);

        assert!(*workers_shutdown.borrow());
    }
}
