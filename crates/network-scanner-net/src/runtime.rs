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
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let poller = polling::Poller::new()?;
        let (sender, receiver) = crossbeam::channel::bounded(QUEUE_CAPACITY);
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
                let mut map = HashMap::new();
                loop {
                    if self.is_terminated.load(Ordering::Acquire) {
                        break;
                    }

                    tracing::debug!("polling events");
                    events.clear();
                    if let Err(e) = self.poller.wait(&mut events, None) {
                        tracing::error!(error = ?e, "failed to poll events");
                        self.is_terminated.store(true, Ordering::SeqCst);
                        break;
                    };

                    while let Ok(event) = receiver.try_recv() {
                        match event {
                            RegisterEvent::Register { id, waker } => {
                                map.insert(id, waker);
                            }
                            RegisterEvent::Unregister { id } => {
                                map.remove(&id);
                            }
                        }
                    }

                    map.retain(|id, waker| {
                        if events.iter().any(|event| event.key == *id) {
                            waker.wake_by_ref();
                            false
                        } else {
                            true
                        }
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
        self.sender
            .send(RegisterEvent::Register { id: event.key, waker })
            .with_context(|| "failed to send register event to register loop")
    }

    pub(crate) fn unregister(&self, id: usize) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }
        self.sender
            .send(RegisterEvent::Unregister { id })
            .with_context(|| "failed to send unregister event to register loop")
    }
}

#[derive(Debug)]
enum RegisterEvent {
    Register { id: usize, waker: Waker },
    Unregister { id: usize },
}
