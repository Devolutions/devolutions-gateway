use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::Waker,
};

use anyhow::Context;
use crossbeam::channel::{Receiver, Sender};
use parking_lot::Mutex;
use polling::{Event, Events};
use socket2::Socket;

use crate::{socket::AsyncRawSocket, ScannnerNetError};

#[derive(Debug)]
pub struct Socket2Runtime {
    poller: Arc<polling::Poller>,
    next_socket_id: AtomicUsize,
    is_terminated: Arc<AtomicBool>,
    register_sender: Sender<RegisterEvent>,
    event_receiver: Receiver<Event>,
    event_cache: Mutex<HashSet<EventWrapper>>,
}

impl Drop for Socket2Runtime {
    fn drop(&mut self) {
        tracing::trace!(covmark = "socket2_runtime_drop");

        self.is_terminated.store(true, Ordering::SeqCst);

        let _ = self // ignore errors, cannot handle it here
            .poller
            .notify()
            .map_err(|e| tracing::error!("failed to notify poller: {:?}", e));

        // Event loop will terminate after this.
        // The register loop will also terminate because of sender is dropped.
    }
}

const QUEUE_CAPACITY: usize = 1024;
impl Socket2Runtime {
    /// Create a new runtime with a queue capacity, default is 1024.
    pub fn new(queue_capacity: Option<usize>) -> anyhow::Result<Arc<Self>> {
        let poller = polling::Poller::new()?;

        let (register_sender, register_receiver) =
            crossbeam::channel::bounded(queue_capacity.unwrap_or(QUEUE_CAPACITY));

        let (event_sender, event_receiver) = crossbeam::channel::bounded(queue_capacity.unwrap_or(QUEUE_CAPACITY));

        let runtime = Self {
            poller: Arc::new(poller),
            next_socket_id: AtomicUsize::new(0),
            is_terminated: Arc::new(AtomicBool::new(false)),
            register_sender,
            event_receiver,
            event_cache: Mutex::new(HashSet::new()),
        };
        let runtime = Arc::new(runtime);
        runtime.start_loop(register_receiver, event_sender)?;
        Ok(runtime)
    }

    pub fn new_socket(
        self: &Arc<Self>,
        domain: socket2::Domain,
        ty: socket2::Type,
        protocol: Option<socket2::Protocol>,
    ) -> anyhow::Result<AsyncRawSocket> {
        let socket = socket2::Socket::new(domain, ty, protocol)?;
        let id = self.next_socket_id.fetch_add(1, Ordering::SeqCst);
        unsafe {
            self.poller.add(&socket, Event::all(id))?;
        }
        Ok(AsyncRawSocket::from_socket(socket, id, self.clone())?)
    }

    pub(crate) fn remove_socket(&self, socket: &socket2::Socket, id: usize) -> anyhow::Result<()> {
        self.poller.delete(socket)?;
        // remove all events related to this socket
        self.event_cache.lock().retain(|event| id == event.0.key);
        Ok(())
    }

    fn start_loop(
        &self,
        register_receiver: Receiver<RegisterEvent>,
        event_sender: Sender<Event>,
    ) -> anyhow::Result<()> {
        // To prevent an Arc cycle with the Arc<Socket2Runtime>, we added additional indirection.
        // Otherwise, the reference in the new thread would prevent the runtime from being dropped and shutdown.
        let poller = self.poller.clone();
        let is_terminated = self.is_terminated.clone();

        std::thread::Builder::new()
            .name("[raw-socket]:io-event-loop".to_string())
            .spawn(move || {
                let mut events = Events::with_capacity(NonZeroUsize::new(1024).unwrap());
                tracing::debug!("starting io event loop");
                // events registered but not happened yet
                let mut events_registered = HashMap::new();

                // events happened but not registered yet
                let mut events_happened = HashMap::new();

                loop {
                    if is_terminated.load(Ordering::Acquire) {
                        break;
                    }

                    tracing::debug!("polling events");
                    if let Err(e) = poller.wait(&mut events, None) {
                        tracing::error!(error = ?e, "failed to poll events");
                        is_terminated.store(true, Ordering::SeqCst);
                        break;
                    };
                    for event in events.iter() {
                        tracing::trace!(?event, "event happened");
                        events_happened.insert(event.key, event);
                    }
                    events.clear();

                    while let Ok(event) = register_receiver.try_recv() {
                        match event {
                            RegisterEvent::Register { id, waker } => {
                                events_registered.insert(id, waker);
                            }
                            RegisterEvent::Unregister { id } => {
                                events_registered.remove(&id);
                            }
                        }
                    }

                    let intersection = events_happened
                        .keys()
                        .filter(|key| events_registered.contains_key(key))
                        .cloned()
                        .collect::<Vec<_>>();

                    intersection.into_iter().for_each(|ref key| {
                        let event = events_happened.remove(key).unwrap();
                        let waker = events_registered.remove(key).unwrap();
                        let _ = event_sender.try_send(event);
                        waker.wake_by_ref();
                        tracing::trace!(?event, "waking up waker");
                    });
                }
                tracing::info!("io event loop terminated");
            })
            .with_context(|| "failed to spawn io event loop thread")?;

        Ok(())
    }

    /// Ideally, we should have a dedicated thread to handle events we received, but we don't really want to spawn a second thread
    /// Alternatively, we can have all socket futures call this function to check if there is any event for them.
    /// The number of times the socket futures is polled is almost guaranteed to be more than the number of registration we received.
    /// hence the event receiver will not be blocked.
    pub(crate) fn check_event(&self, event: Event, remove: bool) -> Option<Event> {
        let mut event_cache = self.event_cache.lock();
        while let Ok(event) = self.event_receiver.try_recv() {
            event_cache.insert(event.into());
        }
        tracing::debug!("checking event cache {:?}", event_cache);

        let event = if remove {
            event_cache.take(&event.into())
        } else if event_cache.contains(&event.into()) {
            Some(event.into())
        } else {
            None
        };

        event.map(|event| event.into_inner())
    }

    pub(crate) fn check_event_with_id(&self, id: usize, remove: bool) -> Vec<Event> {
        let mut event_cache = self.event_cache.lock();
        while let Ok(event) = self.event_receiver.try_recv() {
            event_cache.insert(event.into());
        }
        let event_interested = vec![
            Event::readable(id),
            Event::writable(id),
            Event::all(id),
            Event::none(id),
        ];
        let mut res = vec![];

        if remove {
            event_interested.into_iter().for_each(|event| {
                if let Some(event) = event_cache.take(&event.into()) {
                    res.push(event.into_inner());
                }
            });
        } else {
            event_interested.into_iter().for_each(|event| {
                if event_cache.contains(&event.into()) {
                    res.push(event);
                }
            });
        }

        res
    }

    pub(crate) fn register(&self, socket: &Socket, event: Event, waker: Waker) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }

        tracing::trace!(?event, ?socket, "registering event");
        self.poller.modify(socket, event)?;

        // Use try_send instead of send, in case some io events blocked the queue completely,
        // it would be better to drop the register event then block the worker thread or main thread.
        // as the worker thread is shared for the entire application.
        self.register_sender
            .try_send(RegisterEvent::Register { id: event.key, waker })
            .with_context(|| "failed to send register event to register loop")
    }

    pub(crate) fn unregister(&self, id: usize) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }
        self.register_sender
            .try_send(RegisterEvent::Unregister { id })
            .with_context(|| "failed to send unregister event to register loop")
    }
}

#[derive(Debug)]
enum RegisterEvent {
    Register { id: usize, waker: Waker },
    Unregister { id: usize },
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

impl EventWrapper {
    pub(crate) fn into_inner(self) -> Event {
        self.0
    }
}
