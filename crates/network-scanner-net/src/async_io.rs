use std::{
    num::NonZeroUsize,
    os::windows::io::{AsRawSocket},
    sync::Arc,
};

use polling::{Event, Events};
use socket2::Socket;
use tokio::sync::{Mutex};

use crate::tokio_raw_socket::TokioRawSocket;

#[derive(Debug)]
pub struct AsyncIoRuntime {
    poller: Arc<polling::Poller>,
    socket_id: usize,
    loop_handle: Option<std::thread::JoinHandle<()>>,
    waiting_list: Arc<Mutex<Vec<SocketWaiter>>>,
}

#[derive(Debug)]
struct SocketWaiter {
    id: usize,
    waker: std::task::Waker,
}

impl AsyncIoRuntime {
    pub fn new() -> anyhow::Result<Self> {
        let poller = Arc::new(polling::Poller::new()?);
        Ok(Self {
            poller,
            socket_id: 0,
            loop_handle: None,
            waiting_list: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn get_handle(self) -> AsyncIoHandle {
        AsyncIoHandle {
            runtime: Arc::new(Mutex::new(self)),
        }
    }

    fn add_socket(&mut self, socket: &socket2::Socket) -> anyhow::Result<usize> {
        let id = self.get_socket_id();
        unsafe {
            self.poller.add(socket.as_raw_socket(), Event::all(id))?;
        }
        Ok(id)
    }

    fn get_socket_id(&mut self) -> usize {
        self.socket_id += 1;
        self.socket_id
    }

    pub fn start_loop(mut self) -> anyhow::Result<AsyncIoHandle> {
        let poller = self.poller.clone();
        let waiting_list = self.waiting_list.clone();
        fn get_map(waiting_list: &Mutex<Vec<SocketWaiter>>) -> std::collections::HashMap<usize, std::task::Waker> {
            let map = waiting_list
                .blocking_lock()
                .iter()
                .map(|waiter| (waiter.id, waiter.waker.clone()))
                .collect::<std::collections::HashMap<_, _>>();
            map
        }
        let thread_builder = std::thread::Builder::new().name("async-io-event-loop".to_string());
        let handle = thread_builder.spawn(move || {
            let mut events = Events::with_capacity(NonZeroUsize::new(1024).unwrap());
            tracing::trace!("starting io event loop");
            loop {
                events.clear();

                tracing::trace!("polling events");
                poller.wait(&mut events, None).expect("polling failed");
                let map = get_map(&waiting_list);
                let mut to_remove = vec![];
                for event in events.iter() {
                    tracing::warn!("event {:?}", event);
                    let key = event.key;
                    map.get(&key).map(|waker| {
                        tracing::warn!("waking up waker {:?}", waker);
                        waker.wake_by_ref();
                        to_remove.push(key);
                    });
                }

                waiting_list
                    .blocking_lock()
                    .retain(|waiter| !to_remove.contains(&waiter.id));
            }
        })?;
        self.loop_handle = Some(handle);
        Ok(self.get_handle())
    }

    async fn awake_when_ready(&self, socket: Arc<Socket>, event: Event, waker: std::task::Waker) -> anyhow::Result<()> {
        let waiter = SocketWaiter {
            id: event.key,
            waker: waker.clone(),
        };

        // acquire lock
        let exist = self
            .waiting_list
            .lock()
            .await
            .iter()
            .any(|waiter| waiter.id == event.key);

        if exist {
            return Ok(());
        }

        self.waiting_list.lock().await.push(waiter);
        self.poller.modify(socket.as_ref(), event)?;

        tracing::debug!("awake_when_ready, modified socket {:?} to poller", socket.as_ref());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AsyncIoHandle {
    runtime: Arc<Mutex<AsyncIoRuntime>>,
}

impl AsyncIoHandle {
    pub async fn new_socket(
        &mut self,
        domain: socket2::Domain,
        ty: socket2::Type,
        protocol: Option<socket2::Protocol>,
    ) -> anyhow::Result<TokioRawSocket> {
        let socket = socket2::Socket::new(domain, ty, protocol)?;
        let id = self.runtime.lock().await.add_socket(&socket)?;
        Ok(TokioRawSocket::from_socket(socket, id, self.clone())?)
    }

    pub(crate) fn awake(&self, socket: Arc<Socket>, id: Event, waker: std::task::Waker) -> anyhow::Result<()> {
        let runtime = self.runtime.clone();
        tokio::task::spawn(async move {
            let runtime = runtime.lock().await;
            runtime.awake_when_ready(socket, id, waker).await
        });

        Ok(())
    }
}
