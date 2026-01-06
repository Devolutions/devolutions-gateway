use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use std::time::Duration;

use anyhow::Context;
use crossbeam::channel::{Receiver, Sender};
use parking_lot::Mutex;
use polling::{Event, Events};
use socket2::Socket;

use crate::ScannnerNetError;
use crate::socket::AsyncRawSocket;

#[derive(Debug)]
pub struct Socket2Runtime {
    poller: Arc<polling::Poller>,
    next_socket_id: AtomicUsize,
    is_terminated: Arc<AtomicBool>,
    register_sender: Sender<RegisterEvent>,
    event_history: Arc<Mutex<HashSet<EventWrapper>>>,
}

impl Drop for Socket2Runtime {
    fn drop(&mut self) {
        trace!(covmark = "socket2_runtime_drop");

        self.is_terminated.store(true, Ordering::SeqCst);

        let _ = self // ignore errors, cannot handle it here
            .poller
            .notify()
            .inspect_err(|error| error!(%error, "Failed to notify poller"));

        // Event loop will terminate after this.
        // The register loop will also terminate because of sender is dropped.
    }
}

const QUEUE_CAPACITY: usize = 8024;
impl Socket2Runtime {
    /// Create a new runtime with a queue capacity, default is 8024.
    pub fn new(queue_capacity: Option<usize>) -> anyhow::Result<Arc<Self>> {
        let poller = polling::Poller::new()?;

        let (register_sender, register_receiver) =
            crossbeam::channel::bounded(queue_capacity.unwrap_or(QUEUE_CAPACITY));

        let event_history = Arc::new(Mutex::new(HashSet::new()));
        let runtime = Self {
            poller: Arc::new(poller),
            next_socket_id: AtomicUsize::new(0),
            is_terminated: Arc::new(AtomicBool::new(false)),
            register_sender,
            event_history: Arc::clone(&event_history),
        };
        let runtime = Arc::new(runtime);
        runtime.start_loop(register_receiver, event_history)?;
        Ok(runtime)
    }

    pub fn new_socket(
        self: &Arc<Self>,
        domain: socket2::Domain,
        ty: socket2::Type,
        protocol: Option<socket2::Protocol>,
    ) -> anyhow::Result<AsyncRawSocket> {
        let socket = Socket::new(domain, ty, protocol)?;
        let id = self.next_socket_id.fetch_add(1, Ordering::SeqCst);
        // SAFETY: TODO: explain safety
        unsafe {
            self.poller.add(&socket, Event::all(id))?;
        }
        Ok(AsyncRawSocket::from_socket(socket, id, Arc::clone(self))?)
    }

    pub(crate) fn remove_socket(&self, socket: &Socket, id: usize) -> anyhow::Result<()> {
        self.poller.delete(socket)?;
        // remove all events related to this socket
        self.remove_events_with_id_from_history(id);
        Ok(())
    }

    fn start_loop(
        &self,
        register_receiver: Receiver<RegisterEvent>,
        event_history: Arc<Mutex<HashSet<EventWrapper>>>,
    ) -> anyhow::Result<()> {
        // We make is_terminated Arc<AtomicBool> and poller Arc<Poller> so that we can clone them and move them into the thread.
        // The reason why we cannot hold a Arc<Socket2Runtime> in the thread is because it will create a cycle reference and the runtime will never be dropped.
        let is_terminated = Arc::clone(&self.is_terminated);
        let poller = Arc::clone(&self.poller);
        std::thread::Builder::new()
            .name("[raw-socket]:io-event-loop".to_owned())
            .spawn(move || {
                let mut events =
                    Events::with_capacity(NonZeroUsize::new(QUEUE_CAPACITY).expect("QUEUE_CAPACITY is non-zero"));

                debug!("Start I/O event loop");

                // Events registered but not happened yet.
                let mut events_registered: HashMap<EventWrapper, Waker> = HashMap::new();

                loop {
                    if is_terminated.load(Ordering::Acquire) {
                        break;
                    }

                    // The timeout 200ms is critical, sometimes the event might be registered after the event happened
                    // the timeout limit will allow the events to be checked periodically.
                    if let Err(error) = poller.wait(&mut events, Some(Duration::from_millis(200))) {
                        error!(%error, "Failed to poll events");
                        is_terminated.store(true, Ordering::SeqCst);
                        break;
                    };

                    for event in events.iter() {
                        trace!(?event);
                        // This is different from just insert, as the event wrapper will have the same hash, it actually does not replace the old one.
                        // by removing the old one first, we can make sure the new one is inserted.
                        event_history.lock().remove(&event.into());
                        event_history.lock().insert(event.into());
                    }
                    events.clear();
                    while let Ok(event) = register_receiver.try_recv() {
                        match event {
                            RegisterEvent::Register { event, waker } => {
                                events_registered.insert(event.into(), waker);
                            }
                            RegisterEvent::Unregister { event } => {
                                events_registered.remove(&event.into());
                            }
                        }
                    }

                    for (event, waker) in events_registered.iter() {
                        if event_history.lock().get(event).is_some() {
                            waker.wake_by_ref();
                        }
                    }
                }
                debug!("I/O event loop terminated");
            })
            .context("failed to spawn io event loop thread")?;

        Ok(())
    }

    pub(crate) fn check_event_with_id(&self, id: usize) -> Vec<Event> {
        let event_interested = vec![
            Event::readable(id),
            Event::writable(id),
            Event::all(id),
            Event::none(id),
        ];

        let mut res = Vec::new();
        for event in event_interested {
            if let Some(event) = self.event_history.lock().get(&event.into()) {
                res.push(event.0);
            }
        }

        res
    }

    pub(crate) fn remove_event_from_history(&self, event: Event) {
        self.event_history.lock().remove(&event.into());
    }

    pub(crate) fn remove_events_with_id_from_history(&self, id: usize) {
        let event_interested = vec![
            Event::readable(id),
            Event::writable(id),
            Event::all(id),
            Event::none(id),
        ];

        for event in event_interested {
            self.event_history.lock().remove(&event.into());
        }
    }

    pub(crate) fn register(&self, socket: &Socket, event: Event, waker: Waker) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_owned()))?;
        }

        trace!(?event, ?socket, "Registering event");
        self.poller.modify(socket, event)?;

        // Use try_send instead of send, in case some io events blocked the queue completely,
        // it would be better to drop the register event then block the worker thread or main thread.
        // as the worker thread is shared for the entire application.
        self.register_sender
            .try_send(RegisterEvent::Register { event, waker })
            .with_context(|| "failed to send register event to register loop")
    }

    pub(crate) fn register_events(&self, socket: &Socket, events: &[Event], waker: Waker) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_owned()))?;
        }

        for event in events {
            trace!(?event, ?socket, "Registering event");
            self.poller.modify(socket, *event)?;
            self.register_sender
                .try_send(RegisterEvent::Register {
                    event: *event,
                    waker: waker.clone(),
                })
                .context("failed to send register event to register loop")?;
        }

        Ok(())
    }

    pub(crate) fn unregister(&self, event: Event) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_owned()))?;
        }
        self.register_sender
            .try_send(RegisterEvent::Unregister { event })
            .context("failed to send unregister event to register loop")?;

        Ok(())
    }
}

#[derive(Debug)]
enum RegisterEvent {
    Register { event: Event, waker: Waker },
    Unregister { event: Event },
}

#[derive(Debug)]
pub struct EventWrapper(Event);

impl Hash for EventWrapper {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.key.hash(state);
        self.0.readable.hash(state);
        self.0.writable.hash(state);
    }
}

impl PartialEq for EventWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.key == other.0.key && self.0.readable == other.0.readable && self.0.writable == other.0.writable
    }
}

impl Eq for EventWrapper {}

impl From<Event> for EventWrapper {
    fn from(event: Event) -> Self {
        Self(event)
    }
}

impl From<&Event> for EventWrapper {
    fn from(event: &Event) -> Self {
        Self(*event)
    }
}
