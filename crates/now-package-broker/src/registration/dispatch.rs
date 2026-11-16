//! Requests the Agent sends over a registered connection and the responses it correlates.
//!
//! See "Commands" in the [package-management contract][contract].
//! A [`ConnectionHandle`] reaches exactly one connection and never falls back to another.
//!
//! [contract]: https://github.com/Devolutions/devolutions-gateway/blob/68baca143ca85c34141a6464dae190998d1aedb2/crates/agent-channel-proto/CONTRACT.package-management.md#registration

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::time::Instant;
use uuid::Uuid;

use super::protocol::{self, RemoteError};

/// Requests awaiting a response on one connection.
pub(super) const MAX_OUTSTANDING_REQUESTS: usize = 8;

const MAX_COMMAND_CHARS: usize = 128;

/// Command that asks UniGetUI to reload its installed-package and available-update lists.
const RESCAN_COMMAND: &str = "RescanInventory";

/// Time UniGetUI has to answer a request that neither changes the system nor waits for a scan.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Time UniGetUI has to answer `ExecutePackageOperation`.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Time UniGetUI has to answer `RescanInventory`, which answers when both scans completed.
///
/// A request that reaches this deadline closes its connection, which leaves a package operation running on it unanswered.
/// The deadline is therefore as long as an operation's, and a caller that cannot wait that long bounds its own wait.
const RESCAN_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Why a request produced no result.
///
/// Only [`RequestError::NotSent`] proves that the request was not written to UniGetUI.
/// Every other variant leaves the effect of a write unknown, and an operation must then be reported as unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The request was never written, so UniGetUI cannot have acted on it.
    NotSent(&'static str),
    /// The request may have been written but no valid answer arrived.
    Unanswered(&'static str),
    /// UniGetUI answered that it did not perform the request.
    Rejected(RemoteError),
}

impl RequestError {
    /// Tells whether the request may have reached UniGetUI.
    pub fn may_have_been_sent(&self) -> bool {
        !matches!(self, Self::NotSent(_))
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSent(reason) => write!(f, "request was not sent: {reason}"),
            Self::Unanswered(reason) => write!(f, "request was not answered: {reason}"),
            Self::Rejected(error) => write!(f, "request was rejected with code {}", error.code),
        }
    }
}

impl std::error::Error for RequestError {}

type Reply = Result<Value, RequestError>;

/// A request queued for the connection loop.
pub(super) struct Command {
    id: Uuid,
    frame: Vec<u8>,
    timeout: Duration,
    /// Held until the response arrives, so the 8 outstanding requests bound holds even when the caller gave up.
    permit: OwnedSemaphorePermit,
    reply: oneshot::Sender<Reply>,
}

/// Sends requests to one registered connection.
#[derive(Debug)]
pub(super) struct ConnectionHandle {
    commands: mpsc::Sender<Command>,
    slots: Arc<Semaphore>,
    rescans: Mutex<Rescans>,
}

/// The outcome of one `RescanInventory`, absent until that request ended.
type RescanOutcome = Option<Result<(), RequestError>>;

/// The `RescanInventory` requests of one connection.
///
/// INVARIANT: Only the rescan in `outstanding` is written, and it is replaced only after it ended, so at most one is outstanding.
#[derive(Debug, Default)]
struct Rescans {
    /// The rescan that was written last, which is outstanding until it carries an outcome.
    outstanding: Option<watch::Receiver<RescanOutcome>>,
    /// The rescan that is held unsent until the outstanding one ends, shared by every caller that arrives meanwhile.
    held: Option<watch::Receiver<RescanOutcome>>,
}

impl ConnectionHandle {
    pub(super) fn new() -> (Arc<Self>, mpsc::Receiver<Command>) {
        // INVARIANT: The queue is as large as the permit count, so a request that holds a permit always fits.
        let (commands, receiver) = mpsc::channel(MAX_OUTSTANDING_REQUESTS);
        let handle = Self {
            commands,
            slots: Arc::new(Semaphore::new(MAX_OUTSTANDING_REQUESTS)),
            rescans: Mutex::default(),
        };
        (Arc::new(handle), receiver)
    }

    /// Tells whether the connection loop has ended.
    pub(super) fn is_closed(&self) -> bool {
        self.commands.is_closed()
    }

    /// Sends one request and waits for its correlated response.
    ///
    /// Never retries.
    /// Dropping the returned future abandons the wait but not the request, which keeps its slot until answered or timed out.
    pub(super) async fn request(&self, command: &str, arguments: Value) -> Reply {
        if !arguments.is_object() {
            return Err(RequestError::NotSent("arguments are not an object"));
        }
        if command.is_empty() || MAX_COMMAND_CHARS < command.chars().count() {
            return Err(RequestError::NotSent("command is empty or too long"));
        }

        let id = Uuid::new_v4();
        let frame = protocol::encode_request(id, command, arguments)
            .ok_or(RequestError::NotSent("request exceeds the frame limit"))?;
        let timeout = match command {
            "ExecutePackageOperation" => OPERATION_TIMEOUT,
            RESCAN_COMMAND => RESCAN_TIMEOUT,
            _ => READ_TIMEOUT,
        };

        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| RequestError::NotSent("too many outstanding requests"))?;
        let (reply, response) = oneshot::channel();
        self.commands
            .try_send(Command {
                id,
                frame,
                timeout,
                permit,
                reply,
            })
            .map_err(|_| RequestError::NotSent("connection is closed"))?;

        response
            .await
            .unwrap_or(Err(RequestError::Unanswered("connection closed")))
    }

    /// Asks UniGetUI to reload its package lists and waits for the answer to a request written after this call.
    ///
    /// A request that was already written says nothing about what changed since, so a caller never shares it.
    /// Callers that arrive while a rescan is outstanding share the next one, which is held until that one ended.
    /// Dropping the returned future abandons only the wait: a written request stays outstanding until it ends, and a held one is still sent.
    pub(super) async fn rescan_inventory(self: &Arc<Self>) -> Result<(), RequestError> {
        let mut outcome = {
            let mut rescans = self.rescans.lock();
            match &rescans.held {
                Some(held) => held.clone(),
                None => {
                    let (publish, outcome) = watch::channel(None);
                    let previous = rescans
                        .outstanding
                        .clone()
                        .filter(|previous| previous.borrow().is_none());
                    if previous.is_some() {
                        rescans.held = Some(outcome.clone());
                    } else {
                        rescans.outstanding = Some(outcome.clone());
                    }
                    // The task owns the request, so a caller that gives up neither cancels it nor lets another start early.
                    tokio::spawn(Arc::clone(self).run_rescan(previous, publish));
                    outcome
                }
            }
        };

        let ended = outcome.wait_for(Option::is_some).await;
        // UNTESTED: A rescan task dropped before it publishes, as when the runtime shuts down, ends this wait instead of hanging it.
        // Check that nothing keeps the sender alive past its task when changing `run_rescan`.
        ended
            .ok()
            .and_then(|outcome| outcome.clone())
            .unwrap_or(Err(RequestError::Unanswered("rescan was abandoned")))
    }

    /// Sends one `RescanInventory` once `previous` ended, and publishes its outcome.
    ///
    /// A held rescan is sent even when no caller waits for it any more, so that its scans cover what changed while `previous` was outstanding.
    async fn run_rescan(
        self: Arc<Self>,
        previous: Option<watch::Receiver<RescanOutcome>>,
        publish: watch::Sender<RescanOutcome>,
    ) {
        if let Some(mut previous) = previous {
            // A sender dropped without an outcome also means that the previous rescan ended.
            let _ = previous.wait_for(Option::is_some).await;

            // Callers join the held rescan under this lock, and it leaves `held` before it is written, so none joins a written request.
            let mut rescans = self.rescans.lock();
            rescans.outstanding = rescans.held.take();
        }

        let outcome = self.request(RESCAN_COMMAND, json!({})).await.map(drop);
        publish.send_replace(Some(outcome));
    }
}

pub(super) enum Event {
    Command(Command),
    Expired,
}

struct Pending {
    reply: oneshot::Sender<Reply>,
    deadline: Instant,
    _permit: OwnedSemaphorePermit,
}

/// The connection loop's side of its requests.
///
/// Dropping it answers every outstanding request as unanswered and every queued one as not sent.
pub(super) struct Dispatcher {
    commands: mpsc::Receiver<Command>,
    pending: HashMap<Uuid, Pending>,
}

impl Dispatcher {
    pub(super) fn new(commands: mpsc::Receiver<Command>) -> Self {
        Self {
            commands,
            pending: HashMap::new(),
        }
    }

    /// Waits for a queued request or for an outstanding one to time out.
    pub(super) async fn next_event(&mut self) -> Event {
        let deadline = self.pending.values().map(|pending| pending.deadline).min();
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            command = self.commands.recv() => match command {
                Some(command) => Event::Command(command),
                // Every handle is gone, so no request can arrive.
                None => std::future::pending().await,
            },
            () = expired => Event::Expired,
        }
    }

    /// Records `command` as outstanding and returns its frame, which the caller must now write.
    ///
    /// The request counts as outstanding before the write, because a failed write may still have delivered it.
    pub(super) fn begin(&mut self, command: Command) -> Option<Vec<u8>> {
        let Command {
            id,
            frame,
            timeout,
            permit,
            reply,
        } = command;

        if self.pending.contains_key(&id) {
            let _ = reply.send(Err(RequestError::NotSent("request id is in use")));
            return None;
        }

        self.pending.insert(
            id,
            Pending {
                reply,
                deadline: Instant::now() + timeout,
                _permit: permit,
            },
        );
        Some(frame)
    }

    /// Delivers a response to the request it answers.
    ///
    /// Returns `false` when no outstanding request has this id, which makes the response unsolicited.
    pub(super) fn complete(&mut self, id: Uuid, outcome: Result<Value, RemoteError>) -> bool {
        let Some(pending) = self.pending.remove(&id) else {
            return false;
        };
        let _ = pending.reply.send(outcome.map_err(RequestError::Rejected));
        true
    }

    /// Answers the requests whose deadline passed as unanswered.
    ///
    /// A late response to them would be unsolicited, so the caller closes the connection afterwards.
    pub(super) fn fail_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(pending) = self.pending.remove(&id) {
                let _ = pending.reply.send(Err(RequestError::Unanswered("request timed out")));
            }
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        for (_, pending) in self.pending.drain() {
            let _ = pending.reply.send(Err(RequestError::Unanswered("connection closed")));
        }

        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            let _ = command.reply.send(Err(RequestError::NotSent("connection closed")));
        }
    }
}
