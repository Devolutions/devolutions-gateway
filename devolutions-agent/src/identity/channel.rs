//! The agent channel of one identity ([CONTRACT.md §7 "Channel (gRPC)"][contract]): the stream in use, and the stream
//! that replaces it.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.md#7-channel-grpc

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use agent_channel_client::{Channel, Closure, ClosureClass, Event, TerminalCode};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use url::Url;

/// What the identity needs from its agent channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Want {
    /// No stream.
    Nothing,
    /// No stream opens, because the outcome of a `confirm` may be unknown, and an authenticated stream stays in use
    /// ([CONTRACT.md §8.1 "Agent renewal"][contract], steps 3–4).
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.md#81-agent-renewal
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
    /// A config pushed on the stream `link`, to acknowledge with `id` once it is stored.
    ConfigUpdate {
        link: LinkId,
        id: String,
        config_json: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinkId(u64);

/// The channel of one stream, as [`Links`] uses it.
pub(super) trait LinkChannel {
    fn ack(&self, correlation_id: &str);

    fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send;
}

impl LinkChannel for Channel {
    fn ack(&self, correlation_id: &str) {
        Channel::ack(self, correlation_id);
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
    notices: mpsc::UnboundedReceiver<Notice>,
    status: watch::Receiver<Status>,
    task: JoinHandle<()>,
}

enum Command<C> {
    Reconcile { want: Want, open: oneshot::Sender<bool> },
    Open { url: Url, key_name: String, channel: C },
    Ack { link: LinkId, correlation_id: String },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Status {
    authenticated: bool,
    /// When the earliest opening of a stream starts or started.
    opening_at: Option<Instant>,
}

impl<C: LinkChannel + Send + 'static> Streams<C> {
    /// Starts the task; it must be called within a Tokio runtime.
    pub(super) fn spawn() -> Self {
        let (commands, command_receiver) = mpsc::unbounded_channel();
        let (notice_sender, notices) = mpsc::unbounded_channel();
        let (status_sender, status) = watch::channel(Status::default());
        // UNTESTED: stream events are handled in their own task, so that a stream that must not reopen is dropped
        // while the runner is blocked, for example on a state lock; otherwise its channel reopens it with a retired key.
        // When changing this, keep `Links::handle` off the runner's task.
        let task = tokio::spawn(run_streams(
            Links::new(),
            command_receiver,
            notice_sender,
            status_sender,
        ));
        Self {
            commands,
            notices,
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

    /// Adds the stream that `channel` opens to `url` with the key `key_name`, as [`Links::open`] does.
    pub(super) fn open(&self, url: Url, key_name: String, channel: C) {
        let _ = self.commands.send(Command::Open { url, key_name, channel });
    }

    /// Acknowledges the message `correlation_id` on the stream `link`, if it is still open.
    pub(super) fn ack(&self, link: LinkId, correlation_id: &str) {
        let _ = self.commands.send(Command::Ack {
            link,
            correlation_id: correlation_id.to_owned(),
        });
    }

    /// Waits until the streams report a notice, which it returns, or their status changes.
    pub(super) async fn wait(&mut self) -> Option<Notice> {
        tokio::select! {
            Some(notice) = self.notices.recv() => Some(notice),
            Ok(()) = self.status.changed() => None,
            else => std::future::pending().await,
        }
    }

    /// Returns the next notice if one is waiting.
    pub(super) fn try_next_notice(&mut self) -> Option<Notice> {
        self.notices.try_recv().ok()
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
    notices: mpsc::UnboundedSender<Notice>,
    status: watch::Sender<Status>,
) {
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Reconcile { want, open }) => {
                    let _ = open.send(links.reconcile(want));
                }
                Some(Command::Open { url, key_name, channel }) => {
                    links.open(url, key_name, channel, Instant::now());
                }
                Some(Command::Ack { link, correlation_id }) => links.ack(link, &correlation_id),
                None => return,
            },
            (link, event) = links.next_event() => links.handle(link, event, Instant::now()),
        }
        while let Some(notice) = links.next_notice() {
            let _ = notices.send(notice);
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
    want: Want,
    /// The stream in use.
    active: Option<Link<C>>,
    /// The stream that replaces `active` once it authenticates ([CONTRACT.md §7.3 "Sequence"][contract], step 6).
    ///
    /// INVARIANT: exists only while `active` is authenticated, so that an authenticated replacement always takes the
    /// place of a stream that was in use.
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.md#73-sequence
    replacement: Option<Link<C>>,
    /// Whether the authority asked for a stream to replace `active`.
    reconnect: bool,
    next_id: u64,
    notices: VecDeque<Notice>,
}

struct Link<C> {
    id: LinkId,
    channel: C,
    url: Url,
    key_name: String,
    state: LinkState,
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
    pub(super) fn new() -> Self {
        Self {
            want: Want::Nothing,
            active: None,
            replacement: None,
            reconnect: false,
            next_id: 0,
            notices: VecDeque::new(),
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
    pub(super) fn reconcile(&mut self, want: Want) -> bool {
        self.want = want;
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

    /// Returns the oldest notice the identity hasn't received.
    pub(super) fn next_notice(&mut self) -> Option<Notice> {
        self.notices.pop_front()
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
                    // `CONTRACT.md` §7.3 step 6: the new stream is open, so the old one closes.
                    self.active = self.replacement.take();
                    self.reconnect = false;
                }
                if let Some(active) = &mut self.active {
                    active.state = LinkState::Authenticated;
                    info!(url = %active.url, "Agent channel authenticated");
                }
            }
            Some(Event::RenewRequested { id, reason }) => {
                info!(%reason, "Agent channel requested a renewal");
                if let Some(link) = self.link(role) {
                    link.channel.ack(&id);
                    let key_name = link.key_name.clone();
                    self.notices.push_back(Notice::RenewRequested { key_name });
                }
            }
            Some(Event::Reconnect { reason, .. }) => {
                info!(%reason, "Agent channel requested a new stream");
                if role == Role::Active && matches!(self.want, Want::Stream { .. }) {
                    self.reconnect = true;
                }
            }
            Some(Event::ConfigUpdate { id, config_json }) => {
                self.notices.push_back(Notice::ConfigUpdate { link, id, config_json });
            }
            Some(Event::Closed { closure, reopen_after }) => self.closed(role, closure, reopen_after, now),
        }
        if was_authenticated && !self.authenticated() {
            self.notices.push_back(Notice::Lost);
        }
        if self.needs_open() {
            self.notices.push_back(Notice::StreamNeeded);
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
            ClosureClass::Terminal(code) => self.notices.push_back(Notice::Terminal(code)),
            ClosureClass::CertificateExpired => self.notices.push_back(Notice::CertificateExpired { key_name }),
            ClosureClass::Transient(_) => {}
        }
        if was_authenticated {
            warn!(
                grpc_code = ?closure.grpc_code,
                error_code = closure.error_code.as_deref(),
                reason = %closure.reason,
                ?reopen_after,
                "Agent channel stream closed"
            );
            self.reconnect = false;
        } else {
            debug!(
                grpc_code = ?closure.grpc_code,
                error_code = closure.error_code.as_deref(),
                reason = %closure.reason,
                ?reopen_after,
                "Agent channel stream did not open"
            );
        }
        match (reopen_after, self.link_mut(role)) {
            (Some(delay), Some(link)) => link.state = LinkState::Opening { at: now + delay },
            _ => self.remove(role),
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

async fn next_link_event<C: LinkChannel>(link: Option<&mut Link<C>>) -> (LinkId, Option<Event>) {
    match link {
        Some(link) => (link.id, link.channel.next_event().await),
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use agent_channel_client::TransientKind;
    use rstest::rstest;

    use super::*;

    /// A channel whose events the test hands to [`Links::handle`]; it records whether it was dropped.
    struct TestChannel(Arc<AtomicBool>);

    impl LinkChannel for TestChannel {
        fn ack(&self, _correlation_id: &str) {}

        fn next_event(&mut self) -> impl Future<Output = Option<Event>> + Send {
            std::future::pending()
        }
    }

    impl Drop for TestChannel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
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
        let dropped = Arc::new(AtomicBool::new(false));
        let link = links.open(url(), key_name.to_owned(), TestChannel(Arc::clone(&dropped)), now);
        (link, dropped)
    }

    fn closed_transiently(reopen_after: Duration) -> Option<Event> {
        Some(Event::Closed {
            closure: Closure {
                class: ClosureClass::Transient(TransientKind::Outage),
                grpc_code: None,
                error_code: None,
                server_time: None,
                reason: "connection reset".to_owned(),
            },
            reopen_after: Some(reopen_after),
        })
    }

    fn notices(links: &mut Links<TestChannel>) -> Vec<Notice> {
        std::iter::from_fn(|| links.next_notice()).collect()
    }

    // A stream that reopens with a retired key draws the terminal `identity_unknown` (`CONTRACT.md` §6 step 4), and
    // no stream opens while the outcome of a `confirm` may be unknown (§8.1 step 3), so a stream that closes in either
    // state must be dropped before its channel reopens it.
    #[rstest]
    #[case::its_key_was_replaced(stream("renewed"))]
    #[case::the_streams_are_held(Want::Hold)]
    fn an_authenticated_stream_that_may_not_reopen_is_dropped_when_it_closes(#[case] want: Want) {
        let now = Instant::now();
        let mut links = Links::new();
        links.reconcile(stream("current"));
        let (link, dropped) = open(&mut links, "current", now);
        links.handle(link, Some(Event::Authenticated), now);
        links.reconcile(want);

        links.handle(link, closed_transiently(Duration::from_secs(1)), now);

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_reconnect_request_wakes_the_runner_and_the_old_stream_closes_once_the_new_one_authenticates() {
        // `CONTRACT.md` §7.3 step 6: the agent opens the new stream, then closes the old one; only the runner can open
        // a stream, so the request reaches it as a notice.
        let now = Instant::now();
        let mut links = Links::new();
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
        // `CONTRACT.md` §8.1 step 3: once `confirm` is sent, no stream may be opening.
        let now = Instant::now();
        let mut links = Links::new();
        links.reconcile(stream("current"));
        let (_link, dropped) = open(&mut links, "current", now);

        links.reconcile(Want::Hold);

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn a_wanted_stream_that_closes_reopens_and_reports_the_loss() {
        // `crates/agent-identity/INTENT.md` ("Schedules"): check-in resumes once no stream has authenticated for 1 h,
        // so the runner learns when the identity's last authenticated stream closes.
        let now = Instant::now();
        let mut links = Links::new();
        links.reconcile(stream("current"));
        let (link, dropped) = open(&mut links, "current", now);
        links.handle(link, Some(Event::Authenticated), now);

        links.handle(link, closed_transiently(Duration::from_secs(1)), now);

        assert!(!dropped.load(Ordering::SeqCst));
        assert!(!links.authenticated());
        assert_eq!(notices(&mut links), [Notice::Lost]);
    }

    #[test]
    fn a_stream_is_opening_until_it_authenticates_and_again_once_its_reopening_starts() {
        // The runner sends `confirm` only while no stream is opening (`CONTRACT.md` §8.1 step 3), and a stream waiting
        // to reopen sends nothing until its backoff ends.
        let opened_at = Instant::now();
        let mut links = Links::new();
        links.reconcile(stream("current"));
        let (link, _dropped) = open(&mut links, "current", opened_at);
        assert_eq!(links.opening_at(), Some(opened_at));

        let closed_at = opened_at + Duration::from_secs(2);
        links.handle(link, closed_transiently(Duration::from_secs(5)), closed_at);
        assert_eq!(links.opening_at(), Some(closed_at + Duration::from_secs(5)));

        links.handle(link, Some(Event::Authenticated), closed_at + Duration::from_secs(6));
        assert_eq!(links.opening_at(), None);
    }
}
