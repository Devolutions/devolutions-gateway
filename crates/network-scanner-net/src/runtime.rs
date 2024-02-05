use std::{
    collections::HashMap,
    hash::Hash,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::Waker,
    time::Duration,
};

use anyhow::Context;
use crossbeam::channel::{Receiver, Sender};
use dashmap::DashSet;

use polling::{Event, Events};
use socket2::Socket;

use crate::{socket::AsyncRawSocket, ScannnerNetError};

#[derive(Debug)]
pub struct Socket2Runtime {
    poller: Arc<polling::Poller>,
    next_socket_id: AtomicUsize,
    is_terminated: Arc<AtomicBool>,
    register_sender: Sender<RegisterEvent>,
    event_history: Arc<DashSet<EventWrapper>>,
}

impl Drop for Socket2Runtime {
    fn drop(&mut self) {
        tracing::debug!("dropping runtime");
        self.is_terminated.store(true, Ordering::SeqCst);
        let _ = self // ignore errors, cannot handle it here
            .poller
            .notify()
            .map_err(|e| tracing::error!("failed to notify poller: {:?}", e));
        // event loop will terminate after this
        // register loop will terminate because of sender is dropped after this.
    }
}

const QUEUE_CAPACITY: usize = 8024;
impl Socket2Runtime {
    /// Create a new runtime with a queue capacity, default is 1024.
    pub fn new(queue_capacity: Option<usize>) -> anyhow::Result<Arc<Self>> {
        let poller = polling::Poller::new()?;

        let (register_sender, register_receiver) =
            crossbeam::channel::bounded(queue_capacity.unwrap_or(QUEUE_CAPACITY));

        let event_history = Arc::new(DashSet::new());
        let runtime = Self {
            poller: Arc::new(poller),
            next_socket_id: AtomicUsize::new(0),
            is_terminated: Arc::new(AtomicBool::new(false)),
            register_sender,
            event_history: event_history.clone(),
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
        self.remove_events_with_id_from_history(id);
        Ok(())
    }

    fn start_loop(
        &self,
        register_receiver: Receiver<RegisterEvent>,
        event_history: Arc<DashSet<EventWrapper>>,
    ) -> anyhow::Result<()> {
        // we make is_terminated Arc<AtomicBool> and poller Arc<Poller> so that we can clone them and move them into the thread
        // we cannot hold a Arc<Socket2Runtime> in the thread, because it will create a cycle reference and the runtime will never be dropped.
        let is_terminated = self.is_terminated.clone();
        let poller = self.poller.clone();
        std::thread::Builder::new()
            .name("[raw-socket]:io-event-loop".to_string())
            .spawn(move || {
                let mut events = Events::with_capacity(NonZeroUsize::new(QUEUE_CAPACITY).unwrap());
                tracing::debug!("starting io event loop");
                // events registered but not happened yet
                let mut events_registered: HashMap<EventWrapper, Waker> = HashMap::new();

                loop {
                    if is_terminated.load(Ordering::Acquire) {
                        break;
                    }

                    if let Err(e) = poller.wait(&mut events, Some(Duration::from_millis(200))) {
                        tracing::error!(error = ?e, "failed to poll events");
                        is_terminated.store(true, Ordering::SeqCst);
                        break;
                    };

                    for event in events.iter() {
                        tracing::trace!(?event, "event happened");
                        event_history.insert(event.into());
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
                        if event_history.get(event).is_some() {
                            waker.wake_by_ref();
                        }
                    }
                }
                tracing::debug!("io event loop terminated");
            })
            .with_context(|| "failed to spawn io event loop thread")?;

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
            if let Some(event) = self.event_history.get(&event.into()) {
                res.push(event.0);
            }
        }

        res
    }

    pub(crate) fn remove_event_from_history(&self, event: Event) {
        self.event_history.remove(&event.into());
    }

    pub(crate) fn remove_events_with_id_from_history(&self, id: usize) {
        let event_interested = vec![
            Event::readable(id),
            Event::writable(id),
            Event::all(id),
            Event::none(id),
        ];

        for event in event_interested {
            self.event_history.remove(&event.into());
        }
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
            .try_send(RegisterEvent::Register { event, waker })
            .with_context(|| "failed to send register event to register loop")
    }

    pub(crate) fn register_events(&self, socket: &Socket, events: &[Event], waker: Waker) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }

        for event in events {
            tracing::trace!(?event, ?socket, "registering event");
            self.poller.modify(socket, *event)?;
            self.register_sender
                .try_send(RegisterEvent::Register {
                    event: *event,
                    waker: waker.clone(),
                })
                .with_context(|| "failed to send register event to register loop")?;
        }

        Ok(())
    }

    pub(crate) fn unregister(&self, event: Event) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }
        self.register_sender
            .try_send(RegisterEvent::Unregister { event })
            .with_context(|| "failed to send unregister event to register loop")?;

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
