use anyhow::Context;
use now_proto_pdu::NowMessage;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, error, info, trace};
use win_api_wrappers::event::Event;
use win_api_wrappers::utils::Pipe;
use win_api_wrappers::wts::WtsVirtualChannel;
use windows::Win32::Foundation::{ERROR_IO_PENDING, GetLastError, WAIT_EVENT, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::RemoteDesktop::{CHANNEL_CHUNK_LENGTH, CHANNEL_PDU_HEADER};
use windows::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

use crate::dvc::channel::WinapiSignaledReceiver;
use crate::dvc::now_message_dissector::NowMessageDissector;

const DVC_CHANNEL_NAME: &str = "Devolutions::Now::Agent";

/// Run main DVC IO loop for `Devolutions::Now::Agent` channel.
pub fn run_dvc_io(
    mut write_rx: WinapiSignaledReceiver<NowMessage<'static>>,
    read_tx: Sender<NowMessage<'static>>,
    stop_event: Event,
) -> Result<(), anyhow::Error> {
    trace!("Opening DVC channel");
    let wts = WtsVirtualChannel::open_dvc(DVC_CHANNEL_NAME)?;

    trace!("Querying DVC channel");
    let channel_file = wts.query_file_handle()?;

    trace!("DVC channel opened");

    let mut pdu_chunk_buffer = [0u8; CHANNEL_CHUNK_LENGTH as usize];
    let mut overlapped = OVERLAPPED::default();
    let mut bytes_read: u32 = 0;

    let mut message_dissector = NowMessageDissector::default();

    let read_event = Event::new_unnamed()?;
    overlapped.hEvent = read_event.raw();

    info!("DVC IO thread is running");

    // Prepare async read operation.
    // SAFETY: Both `channel_file` and event passed to `overlapped` are valid during this call,
    // therefore it is safe to call.
    let read_result: Result<(), windows::core::Error> =
        unsafe { ReadFile(*channel_file, Some(&mut pdu_chunk_buffer), None, Some(&mut overlapped)) };

    ensure_overlapped_io_result(read_result)?;

    loop {
        let events = [read_event.raw(), write_rx.raw_wait_handle(), stop_event.raw()];

        const WAIT_OBJECT_READ_DVC: WAIT_EVENT = WAIT_OBJECT_0;
        const WAIT_OBJECT_WRITE_DVC: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);
        const WAIT_OBJECT_STOP: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 2);

        // SAFETY: No preconditions.
        let wait_status = unsafe { WaitForMultipleObjects(&events, false, INFINITE) };

        match wait_status {
            // Read event is signaled (incoming data from DVC channel).
            WAIT_OBJECT_READ_DVC => {
                trace!("DVC channel read event is signaled");

                // SAFETY: No preconditions.
                unsafe { GetOverlappedResult(*channel_file, &overlapped, &mut bytes_read, false) }?;

                if bytes_read
                    < u32::try_from(size_of::<CHANNEL_PDU_HEADER>())
                        .expect("CHANNEL_PDU_HEADER size always fits into u32")
                {
                    // Channel is closed abruptly; abort loop.
                    return Ok(());
                }

                let chunk_data_size = usize::try_from(bytes_read)
                    .expect("read size can't be breater than CHANNEL_CHUNK_LENGTH, therefore it should fit into usize")
                    .checked_sub(size_of::<CHANNEL_PDU_HEADER>())
                    .expect("read size is less than header size; Correctness of this should be ensured by the OS");

                const HEADER_SIZE: usize = size_of::<CHANNEL_PDU_HEADER>();

                let messages = message_dissector
                    .dissect(&pdu_chunk_buffer[HEADER_SIZE..HEADER_SIZE + chunk_data_size])
                    .context("failed to dissect DVC messages");

                let messages = match messages {
                    Ok(messages) => messages,
                    Err(err) => {
                        error!(?err, "Failed to dissect DVC messages");
                        return Err(err);
                    }
                };

                // Send all messages over the channel.
                for message in messages {
                    debug!(?message, "DVC message received");
                    // We do non-blocking send to avoid blocking the IO thread. Processing
                    // task is expected to be fast enough to keep up with the incoming messages.
                    match read_tx.try_send(message) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            error!("DVC message was dropped due to channel overflow");
                        }
                        Err(e) => {
                            error!("DVC message was dropped due to closed channel");
                            return Err(e.into());
                        }
                    }
                }

                // Prepare async read file operation one more time.
                // SAFETY: No preconditions.
                let result =
                    unsafe { ReadFile(*channel_file, Some(&mut pdu_chunk_buffer), None, Some(&mut overlapped)) };

                ensure_overlapped_io_result(result)?;
            }
            // Write event is signaled (outgoing data to DVC channel).
            WAIT_OBJECT_WRITE_DVC => {
                trace!("DVC channel write event is signaled");

                let message_to_write = write_rx.try_recv()?;
                let message_bytes = now_proto_pdu::ironrdp_core::encode_vec(&message_to_write)?;

                let mut dw_written: u32 = 0;

                // SAFETY: No preconditions.
                unsafe { WriteFile(*channel_file, Some(&message_bytes), Some(&mut dw_written), None)? }
            }
            WAIT_OBJECT_STOP => {
                info!("DVC IO thread is stopped");
                // Stop event is signaled; abort loop.
                return Ok(());
            }
            _ => {
                // Spurious wakeup or wait failure
            }
        };
    }
}

pub fn ensure_overlapped_io_result(result: windows::core::Result<()>) -> Result<(), windows::core::Error> {
    if let Err(error) = result {
        // SAFETY: GetLastError is alwayі safe to call
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(error);
        }
    }

    Ok(())
}

pub struct IoRedirectionPipes {
    pub stdout_read_pipe: Pipe,
    pub stdout_write_pipe: Pipe,

    pub stderr_read_pipe: Pipe,
    pub stderr_write_pipe: Pipe,

    pub stdin_read_pipe: Pipe,
    pub stdin_write_pipe: Pipe,
}

impl IoRedirectionPipes {
    pub fn new() -> anyhow::Result<Self> {
        let (stdout_read_pipe, stdout_write_pipe) = Pipe::new_async_stdout_redirection_pipe()?;
        let (stderr_read_pipe, stderr_write_pipe) = Pipe::new_async_stdout_redirection_pipe()?;
        let (stdin_read_pipe, stdin_write_pipe) = Pipe::new_sync_stdin_redirection_pipe()?;

        Ok(IoRedirectionPipes {
            stdout_read_pipe,
            stdout_write_pipe,
            stderr_read_pipe,
            stderr_write_pipe,
            stdin_read_pipe,
            stdin_write_pipe,
        })
    }
}
