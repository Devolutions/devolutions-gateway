use std::net::IpAddr;

use derive_more::From;
use tokio::sync::{broadcast, mpsc};

use crate::broadcast::BroadcastEvent;
use crate::mdns::MdnsEvent;
use crate::netbios::NetBiosEvent;
use crate::ping::PingEvent;
use crate::port_discovery::TcpKnockEvent;
use crate::scanner::{DnsEvent, TcpKnockWithHost};

macro_rules! define_scanner_event {
    (
        $( $typ:ty => $variant:ident ),* $(,)?
    ) => {
        pub trait Sendable {}

        #[derive(Debug, Clone, From)]
        pub enum ScannerEvent {
            $(
                $variant($typ),
            )*
        }

        $(
            impl Sendable for $typ {}
        )*

    }
}

define_scanner_event! {
    PingEvent => Ping,
    MdnsEvent => Mdns,
    NetBiosEvent => NetBios,
    TcpKnockEvent => TcpKnock,
    TcpKnockWithHost => TcpKnockWithHost,
    BroadcastEvent => Broadcast,
    DnsEvent => Dns,
}

pub trait Splitable<T> {}
macro_rules! define_splitable {
    (
        $recv_event:ident,
        $($typ:ty),* $(,)?
    ) => {

        $(
            impl Splitable<$typ> for $recv_event {}
        )*
    }
}

#[derive(Debug, Clone)]
pub enum RawIpEvent {
    Ping(PingEvent),
    Boardcast(BroadcastEvent),
}

impl TryFrom<ScannerEvent> for TcpKnockEvent {
    type Error = ();

    fn try_from(value: ScannerEvent) -> Result<Self, Self::Error> {
        match value {
            ScannerEvent::TcpKnock(tcp_knock_event) => Ok(tcp_knock_event),
            _ => Err(()),
        }
    }
}

define_splitable! {RawIpEvent, DnsEvent, TcpKnockEvent }
define_splitable! {TcpKnockEvent, TcpKnockWithHost}

impl TryFrom<ScannerEvent> for RawIpEvent {
    type Error = ();

    fn try_from(value: ScannerEvent) -> Result<Self, Self::Error> {
        match value {
            ScannerEvent::Ping(ping_event) => Ok(RawIpEvent::Ping(ping_event)),
            ScannerEvent::Broadcast(boardcast_event) => Ok(RawIpEvent::Boardcast(boardcast_event)),
            _ => Err(()),
        }
    }
}

impl RawIpEvent {
    pub fn success(&self) -> Option<IpAddr> {
        match self {
            RawIpEvent::Ping(PingEvent::Success { ip, .. }) => Some(*ip),
            RawIpEvent::Boardcast(BroadcastEvent::Entry { ip }) => Some(IpAddr::V4(*ip)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<ScannerEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(255);
        Self { sender }
    }

    pub fn sender<T>(&self) -> TypedSender<T> {
        let sender = self.sender.clone();
        TypedSender::new(sender)
    }

    pub fn subscribe<T>(&self) -> TypedReceiver<T> {
        let receiver = self.sender.subscribe();
        TypedReceiver::new(receiver)
    }

    // For not making mistakes, (e.g. send the same event that we receive)
    pub fn split<S, R>(&self) -> (TypedSender<S>, TypedReceiver<R>)
    where
        R: Splitable<S>,
    {
        let sender = self.sender.clone();
        let receiver = self.sender.subscribe();
        (TypedSender::new(sender), TypedReceiver::new(receiver))
    }
}

pub struct TypedReceiver<T> {
    receiver: broadcast::Receiver<ScannerEvent>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> TypedReceiver<T> {
    fn new(receiver: broadcast::Receiver<ScannerEvent>) -> Self {
        Self {
            receiver,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> TypedReceiver<T>
where
    T: TryFrom<ScannerEvent, Error = ()>,
{
    pub async fn recv(&mut self) -> Result<T, broadcast::error::RecvError> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    if let Ok(typed_event) = T::try_from(event) {
                        return Ok(typed_event);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[derive(Clone)]
pub struct TypedSender<T> {
    sender: broadcast::Sender<ScannerEvent>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> TypedSender<T> {
    fn new(sender: broadcast::Sender<ScannerEvent>) -> Self {
        Self {
            sender,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> TypedSender<T>
where
    T: Into<ScannerEvent> + Sendable,
{
    pub fn send(&self, event: T) -> Result<usize, broadcast::error::SendError<ScannerEvent>> {
        self.sender.send(event.into())
    }

    pub async fn send_from(&self, mut receiver: mpsc::Receiver<T>) -> anyhow::Result<()> {
        while let Some(event) = receiver.recv().await {
            self.send(event)?;
        }
        Ok(())
    }
}
