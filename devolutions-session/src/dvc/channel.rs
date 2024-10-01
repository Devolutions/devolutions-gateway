use std::fmt::Debug;

use tokio::sync::mpsc::{self, Receiver, Sender};
use win_api_wrappers::event::Event;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::SetEvent;

const IO_CHANNEL_SIZE: usize = 100;

/// Mpsc channel with WinAPI event signaling.
#[derive(Debug, Clone)]
pub struct WinapiSignaledSender<T> {
    tx: Sender<T>,
    event: Event,
}

impl<T: Send + Sync + Debug + 'static> WinapiSignaledSender<T> {
    pub async fn send(&self, message: T) -> anyhow::Result<()> {
        self.tx.send(message).await?;

        // DVC IO loop is controlled by WinAPI events signaling, therefore we need to fire event to
        // notify DVC IO loop about new incoming message.

        // SAFETY: No preconditions.
        unsafe {
            SetEvent(self.event.raw())?;
        }
        Ok(())
    }

    pub fn blocking_send(&self, message: T) -> anyhow::Result<()> {
        self.tx.blocking_send(message)?;

        // SAFETY: No preconditions.
        unsafe {
            SetEvent(self.event.raw())?;
        }
        Ok(())
    }
}

pub struct WinapiSignaledReceiver<T> {
    rx: Receiver<T>,
    event: Event,
}

impl<T: Send + Sync + Debug + 'static> WinapiSignaledReceiver<T> {
    pub fn try_recv(&mut self) -> anyhow::Result<T> {
        let value = self.rx.try_recv()?;
        Ok(value)
    }

    pub fn raw_event(&self) -> HANDLE {
        self.event.raw()
    }
}

/// Creates WinAPI signaled mpsc channel.
pub fn winapi_signaled_mpsc_channel<T>() -> anyhow::Result<(WinapiSignaledSender<T>, WinapiSignaledReceiver<T>)> {
    // Create WinAPI event.

    let event = Event::new_unnamed()?;

    let (tx, rx) = mpsc::channel(IO_CHANNEL_SIZE);

    Ok((
        WinapiSignaledSender {
            tx,
            event: event.clone(),
        },
        WinapiSignaledReceiver { rx, event },
    ))
}

pub fn bounded_mpsc_channel<T>() -> anyhow::Result<(Sender<T>, Receiver<T>)> {
    let (tx, rx) = mpsc::channel(IO_CHANNEL_SIZE);

    Ok((tx, rx))
}
