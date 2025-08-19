use std::fmt::Debug;

use tokio::sync::mpsc::{self, Receiver, Sender};
use win_api_wrappers::semaphore::Semaphore;
use windows::Win32::Foundation::HANDLE;

const IO_CHANNEL_SIZE: usize = 100;

/// Mpsc channel with WinAPI event signaling.
#[derive(Debug, Clone)]
pub struct WinapiSignaledSender<T> {
    tx: Sender<T>,
    semaphore: Semaphore,
}

impl<T: Send + Sync + Debug + 'static> WinapiSignaledSender<T> {
    pub async fn send(&self, message: T) -> anyhow::Result<()> {
        self.tx.send(message).await?;

        // DVC IO loop is controlled by WinAPI events signaling, therefore we need to fire event to
        // notify DVC IO loop about new incoming message.

        self.semaphore.release(1)?;

        Ok(())
    }

    pub fn try_send(&self, message: T) -> anyhow::Result<()> {
        self.tx.try_send(message)?;

        self.semaphore.release(1)?;
        Ok(())
    }

    pub fn blocking_send(&self, message: T) -> anyhow::Result<()> {
        self.tx.blocking_send(message)?;

        self.semaphore.release(1)?;

        Ok(())
    }
}

pub struct WinapiSignaledReceiver<T> {
    rx: Receiver<T>,
    semaphore: Semaphore,
}

impl<T: Send + Sync + Debug + 'static> WinapiSignaledReceiver<T> {
    pub fn try_recv(&mut self) -> anyhow::Result<T> {
        let value = self.rx.try_recv()?;
        Ok(value)
    }

    pub fn raw_wait_handle(&self) -> HANDLE {
        self.semaphore.raw()
    }
}

/// Creates WinAPI signaled mpsc channel.
pub fn winapi_signaled_mpsc_channel<T>() -> anyhow::Result<(WinapiSignaledSender<T>, WinapiSignaledReceiver<T>)> {
    // Create WinAPI event.

    let maximum_count = IO_CHANNEL_SIZE
        .try_into()
        .expect("Channel size is too large for underlying WinAPI semaphore");

    let semaphore = Semaphore::new_unnamed(0, maximum_count)?;

    let (tx, rx) = mpsc::channel(IO_CHANNEL_SIZE);

    Ok((
        WinapiSignaledSender {
            tx,
            semaphore: semaphore.clone(),
        },
        WinapiSignaledReceiver { rx, semaphore },
    ))
}

pub fn bounded_mpsc_channel<T>() -> anyhow::Result<(Sender<T>, Receiver<T>)> {
    let (tx, rx) = mpsc::channel(IO_CHANNEL_SIZE);

    Ok((tx, rx))
}
