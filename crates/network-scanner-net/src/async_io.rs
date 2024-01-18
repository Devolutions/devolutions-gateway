use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc,
    },
};

use anyhow::Context;
use crossbeam::channel::Receiver;
use parking_lot::Mutex;
use polling::{Event, Events};
use socket2::Socket;

use crate::async_raw_socket::AsyncRawSocket;

#[derive(Debug)]
pub struct Socket2Runtime {
    poller: polling::Poller,
    next_socket_id: AtomicUsize,
    is_terminated: AtomicBool,
    map: Arc<Mutex<HashMap<usize, std::task::Waker>>>,
    sender: crossbeam::channel::Sender<(Event, std::task::Waker, Arc<Socket>)>,
}

impl Drop for Socket2Runtime {
    fn drop(&mut self) {
        self.is_terminated.store(true, std::sync::atomic::Ordering::SeqCst);
        self.poller
            .notify()
            .map_err(|e| tracing::error!("failed to notify poller: {:?}", e))
            .ok();
        // event loop will terminate after this
        // register loop will terminate becase of sender is dropped after this.
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
            map: Arc::new(Mutex::new(HashMap::new())),
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
        let id = self.next_socket_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        unsafe {
            self.poller.add(&socket, Event::all(id))?;
        }
        Ok(AsyncRawSocket::from_socket(socket, id, self.clone())?)
    }

    pub(crate) fn remove_socket(&self, socket: &socket2::Socket) -> anyhow::Result<()> {
        self.poller.delete(socket)?;
        Ok(())
    }

    fn start_register_loop(
        self: Arc<Self>,
        receiver: Receiver<(Event, std::task::Waker, Arc<Socket>)>,
    ) -> anyhow::Result<()> {
        std::thread::Builder::new()
            .name("[raw-socket]:register-loop | ".to_string())
            .spawn(move || {
                tracing::debug!("starting event register loop");
                loop {
                    let (event, waker, socket) = match receiver.recv() {
                        //recv is blocking if channel is empty
                        Ok(a) => a,
                        Err(_) => break,
                    };

                    {
                        tracing::trace!(?event, ?socket, "registering event");
                        let mut map = self.map.lock();
                        if map.contains_key(&event.key) {
                            continue;
                        }
                        map.insert(event.key, waker);
                    } // drop the lock before registering the event

                    self.poller
                        .modify(socket, event)
                        .map_err(|e| tracing::warn!(error = ?e, "Event registration failed"))
                        .ok(); // cannot handle this error
                    tracing::trace!("event registered successfully");
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
                    if self.is_terminated.load(std::sync::atomic::Ordering::Acquire) {
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
                self.is_terminated.store(true, std::sync::atomic::Ordering::SeqCst);
            })?;
        Ok(())
    }

    pub(crate) fn register(&self, socket: Arc<Socket>, event: Event, waker: std::task::Waker) -> anyhow::Result<()> {
        //non-blocking if channel is not full
        self.sender
            .send((event, waker, socket))
            .with_context(|| "failed to send event to register loop")
    }
}
