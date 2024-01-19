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
use parking_lot::Mutex;
use polling::{Event, Events};
use socket2::Socket;

use crate::{socket::AsyncRawSocket, ScannnerNetError};

#[derive(Debug)]
pub struct Socket2Runtime {
    poller: polling::Poller,
    next_socket_id: AtomicUsize,
    is_terminated: AtomicBool,
    map: Mutex<HashMap<usize, Waker>>,
    sender: Sender<RegisterEvent>,
}

impl Drop for Socket2Runtime {
    fn drop(&mut self) {
        self.is_terminated.store(true, Ordering::SeqCst);
        let _ = self // ignore errors, cannot handle it here
            .poller
            .notify()
            .map_err(|e| tracing::error!("failed to notify poller: {:?}", e));
        // event loop will terminate after this
        // register loop will terminate because of sender is dropped after this.
    }
}

impl Socket2Runtime {
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let poller = polling::Poller::new()?;
        //unbounded channel performance is worse, but prevents sender from blocking, in case of Tokio crashes completely
        let (sender, receiver) = crossbeam::channel::unbounded();
        let runtime = Self {
            poller,
            next_socket_id: AtomicUsize::new(0),
            map: Mutex::new(HashMap::new()),
            is_terminated: AtomicBool::new(false),
            sender,
        };
        let runtime = Arc::new(runtime);
        runtime.clone().start_register_loop(receiver)?;
        runtime.clone().start_loop()?;
        Ok(runtime)
    }

    pub fn new_socket(
        self: &Arc<Self>,
        domain: socket2::Domain,
        ty: socket2::Type,
        protocol: Option<socket2::Protocol>,
    ) -> anyhow::Result<AsyncRawSocket> {
        let socket = socket2::Socket::new(domain, ty, protocol)?;
        socket.set_nonblocking(true)?;
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

    fn start_register_loop(self: Arc<Self>, receiver: Receiver<RegisterEvent>) -> anyhow::Result<()> {
        std::thread::Builder::new()
            .name("[raw-socket]:register-loop | ".to_string())
            .spawn(move || {
                tracing::debug!("starting event register loop");
                loop {
                    let event = match receiver.recv() {
                        //recv is blocking if channel is empty
                        Ok(a) => a,
                        Err(_) => break,
                    };

                    match event {
                        RegisterEvent::Register { socket, event, waker } => {
                            {
                                tracing::trace!(?event, ?socket, "registering event");
                                let mut map = self.map.lock();
                                if map.contains_key(&event.key) {
                                    continue;
                                }
                                map.insert(event.key, waker);
                            } // drop the lock before registering the event

                            let _ = self
                                .poller // cannot handle this error
                                .modify(socket, event)
                                .map_err(|e| tracing::warn!(error = ?e, "Event registration failed"));
                            tracing::trace!("event registered successfully");
                        }

                        RegisterEvent::Unregister { socket, id } => {
                            {
                                self.map.lock().remove(&id);
                            }
                            let _ = self
                                .poller // cannot handle this error
                                .modify(&socket, Event::none(id))
                                .map_err(|e| tracing::warn!(error = ?e, "Event unregistration failed"));

                            tracing::trace!("event unregistered successfully");
                        }
                    }
                }
                tracing::warn!("register loop terminated")
            })?;
        Ok(())
    }

    fn start_loop(self: Arc<Self>) -> anyhow::Result<()> {
        std::thread::Builder::new()
            .name("[raw-socket]:io-event-loop | ".to_string())
            .spawn(move || {
                let mut events = Events::with_capacity(NonZeroUsize::new(1024).unwrap());
                tracing::debug!("starting io event loop");
                loop {
                    if self.is_terminated.load(Ordering::Acquire) {
                        break;
                    }

                    tracing::debug!("polling events");
                    events.clear();
                    self.poller.wait(&mut events, None).expect("polling failed");
                    {
                        // Important: lock after blocking poll
                        let mut map = self.map.lock();
                        for event in events.iter() {
                            tracing::trace!(?event, "events polled");
                            let key = event.key;
                            if let Some(waker) = map.get(&key) {
                                waker.wake_by_ref();
                                tracing::trace!(?key, "waker called");
                                map.remove(&key);
                            }
                        }
                    }
                }
                self.is_terminated.store(true, Ordering::SeqCst);
            })?;
        Ok(())
    }

    pub(crate) fn register(&self, socket: Arc<Socket>, event: Event, waker: Waker) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }
        //The sender will be non-blocking if the channel is not full
        //This will prevent Tokio or other async runtime from panicking on blocking operation
        self.sender
            .send(RegisterEvent::Register { socket, event, waker })
            .with_context(|| "failed to send register event to register loop")
    }

    pub(crate) fn unregister(&self, socket: Arc<Socket>, id: usize) -> anyhow::Result<()> {
        if self.is_terminated.load(Ordering::Acquire) {
            Err(ScannnerNetError::AsyncRuntimeError("runtime is terminated".to_string()))?;
        }
        self.sender
            .send(RegisterEvent::Unregister { socket, id })
            .with_context(|| "failed to send unregister event to register loop")
    }
}

enum RegisterEvent {
    Register {
        socket: Arc<Socket>,
        event: Event,
        waker: Waker,
    },
    Unregister {
        socket: Arc<Socket>,
        id: usize,
    },
}
