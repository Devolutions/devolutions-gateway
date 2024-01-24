use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::Waker,
};

use anyhow::Context;
use crossbeam::channel::{Receiver, Sender};
use polling::{Event, Events};
use socket2::Socket;

use crate::{socket::AsyncRawSocket, ScannnerNetError};

#[derive(Debug)]
pub struct Socket2Runtime {
    poller: polling::Poller,
    next_socket_id: AtomicUsize,
    is_terminated: AtomicBool,
    sender: Sender<RegisterEvent>,
}

impl Drop for Socket2Runtime {
    fn drop(&mut self) {
        self.is_terminated.store(true, Ordering::SeqCst);
        tracing::debug!("dropping runtime");
        let _ = self // ignore errors, cannot handle it here
            .poller
            .notify()
            .map_err(|e| tracing::error!("failed to notify poller: {:?}", e));
        // event loop will terminate after this
        // register loop will terminate because of sender is dropped after this.
    }
}

const QUEUE_CAPACITY: usize = 1024;
impl Socket2Runtime {
    /// Create a new runtime with a queue capacity, default is 1024.
    pub fn new(queue_capacity: Option<usize>) -> anyhow::Result<Arc<Self>> {
        let poller = polling::Poller::new()?;
        let (sender, receiver) = crossbeam::channel::bounded(queue_capacity.unwrap_or(QUEUE_CAPACITY));
        let runtime = Self {
            poller,
            next_socket_id: AtomicUsize::new(0),
            is_terminated: AtomicBool::new(false),
            sender,
        };
        let runtime = Arc::new(runtime);
        runtime.clone().start_loop(receiver)?;
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

    pub(crate) fn remove_socket(&self, socket: &socket2::Socket) -> anyhow::Result<()> {
        self.poller.delete(socket)?;
        Ok(())
    }

    fn start_loop(self: Arc<Self>, receiver: Receiver<RegisterEvent>) -> anyhow::Result<()> {
        std::thread::Builder::new()
            .name("[raw-socket]:io-event-loop".to_string())
            .spawn(move || {
                let mut events = Events::with_capacity(NonZeroUsize::new(1024).unwrap());
                tracing::debug!("starting io event loop");
                let mut events_registered = HashMap::new();
                let mut events_happend = HashMap::new();
                loop {
                    if self.is_terminated.load(Ordering::Acquire) {
                        break;
                    }

                    tracing::debug!("polling events");
                    if let Err(e) = self.poller.wait(&mut events, None) {
                        tracing::error!(error = ?e, "failed to poll events");
                        self.is_terminated.store(true, Ordering::SeqCst);
                        break;
                    };
                    for event in events.iter() {
                        tracing::trace!(?event, "event happend");
                        events_happend.insert(event.key, event);
                    }
                    events.clear();

                    while let Ok(event) = receiver.try_recv() {
                        match event {
                            RegisterEvent::Register { id, waker } => {
                                events_registered.insert(id, waker);
                            }
                            RegisterEvent::Unregister { id } => {
                                events_registered.remove(&id);
                            }
                        }
                    }

                    let intersection = events_happend
                        .keys()
                        .filter(|key| events_registered.contains_key(key))
                        .cloned()
                        .collect::<Vec<_>>();

                    intersection.into_iter().for_each(|ref key| {
                        let event = events_happend.remove(key).unwrap();
                        let waker = events_registered.remove(key).unwrap();
                        waker.wake_by_ref();
                        tracing::trace!(?event, "waking up waker");
                    });
                }
            })
            .with_context(|| "failed to spawn io event loop thread")?;

        Ok(())
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
        self.sender
            .try_send(RegisterEvent::Register { id: event.key, waker })
            .with_context(|| "failed to send register event to register loop")
    }

    pub(crate) fn unregister(&self, id: usize) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }
        self.sender
            .try_send(RegisterEvent::Unregister { id })
            .with_context(|| "failed to send unregister event to register loop")
    }
}

#[derive(Debug)]
enum RegisterEvent {
    Register { id: usize, waker: Waker },
    Unregister { id: usize },
}
