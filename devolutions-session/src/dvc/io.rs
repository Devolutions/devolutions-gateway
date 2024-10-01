use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use windows::core::{Owned, PCSTR};
use windows::Win32::Foundation::{
    DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_IO_PENDING, HANDLE, WAIT_EVENT, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::RemoteDesktop::{
    WTSVirtualChannelOpenEx, WTSVirtualChannelQuery, WTSVirtualFileHandle, CHANNEL_CHUNK_LENGTH, CHANNEL_PDU_HEADER,
    WTS_CHANNEL_OPTION_DYNAMIC, WTS_CURRENT_SESSION,
};
use windows::Win32::System::Threading::{GetCurrentProcess, WaitForMultipleObjects, INFINITE};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

use now_proto_pdu::NowMessage;
use win_api_wrappers::event::Event;
use win_api_wrappers::utils::Pipe;
use win_api_wrappers::wts::{WTSMemory, WTSVirtualChannel};

use crate::dvc::channel::WinapiSignaledReceiver;
use crate::dvc::now_message_dissector::NowMessageDissector;

const DVC_CHANNEL_NAME: &str = "Devolutions::Now::Agent";

/// Run main DVC IO loop for `Devolutions::Now::Agent` channel.
pub fn run_dvc_io(
    mut write_rx: WinapiSignaledReceiver<NowMessage>,
    read_tx: Sender<NowMessage>,
    stop_event: Event,
) -> Result<(), anyhow::Error> {
    let channel_file = open_agent_dvc_channel_impl()?;

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
        let events = [read_event.raw(), write_rx.raw_event(), stop_event.raw()];

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
                        .expect("BUG CHANNEL_PDU_HEADER size always fits into u32")
                {
                    // Channel is closed abruptly; abort loop.
                    return Ok(());
                }

                let chunk_data_size = usize::try_from(bytes_read)
                    .expect(
                        "BUG: Read size can't be breater than CHANNEL_CHUNK_LENGTH, therefore it should fit into usize",
                    )
                    .checked_sub(size_of::<CHANNEL_PDU_HEADER>())
                    .expect("BUG: Read size is less than header size; Correctness of this should be ensured by the OS");

                const HEADER_SIZE: usize = size_of::<CHANNEL_PDU_HEADER>();

                let messages = message_dissector
                    .dissect(&pdu_chunk_buffer[HEADER_SIZE..HEADER_SIZE + chunk_data_size])
                    .expect("BUG: Failed to dissect messages");

                // Send all messages over the channel.
                for message in messages {
                    debug!(?message, "DVC message received");
                    // We do non-blocking send to avoid blocking the IO thread. Processing
                    // task is expected to be fast enough to keep up with the incoming messages.
                    match read_tx.try_send(message) {
                        Ok(_) => {
                            trace!("Received DVC message is sent to the processing channel");
                        }
                        Err(TrySendError::Full(_)) => {
                            trace!("DVC message is dropped due to busy channel");
                        }
                        Err(e) => {
                            trace!("DVC message is dropped due to closed channel");
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
                let message_bytes = ironrdp::core::encode_vec(&message_to_write)?;

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

fn open_agent_dvc_channel_impl() -> anyhow::Result<Owned<HANDLE>> {
    let channel_name_wide = PCSTR::from_raw(DVC_CHANNEL_NAME.as_ptr());

    trace!("Opening DVC channel");

    #[allow(clippy::undocumented_unsafe_blocks)] // false positive
    // SAFETY: No preconditions.
    let raw_wts_handle =
        unsafe { WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, channel_name_wide, WTS_CHANNEL_OPTION_DYNAMIC) }?;

    // SAFETY: `WTSVirtualChannelOpenEx` always returns a valid handle on success.
    let wts = unsafe { WTSVirtualChannel::new(raw_wts_handle) };

    let mut channel_file_handle_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

    let mut len: u32 = 0;

    trace!("Querying DVC channel");

    // SAFETY: It is safe to call `WTSVirtualChannelQuery` with valid channel and
    // destination pointers.
    unsafe {
        WTSVirtualChannelQuery(
            wts.raw(),
            WTSVirtualFileHandle,
            &mut channel_file_handle_ptr as *mut _,
            &mut len,
        )
    }?;

    // SAFETY: `channel_file_handle_ptr` is always a valid pointer to a handle on success.
    let channel_file_handle_ptr = unsafe { WTSMemory::new(channel_file_handle_ptr) };

    if len != u32::try_from(size_of::<HANDLE>()).expect("HANDLE always fits into u32") {
        return Err(anyhow::anyhow!("Failed to query DVC channel file handle"));
    }

    let mut raw_handle = HANDLE::default();

    // SAFETY: `GetCurrentProcess` is always safe to call.
    let current_process = unsafe { GetCurrentProcess() };

    // SAFETY: `lptargetprocesshandle` is valid and points to `raw_handle` declared above,
    // therefore it is safe to call.
    unsafe {
        DuplicateHandle(
            current_process,
            channel_file_handle_ptr.as_handle(),
            current_process,
            &mut raw_handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )?;
    };

    info!("DVC channel opened");

    // SAFETY: `DuplicateHandle` is always safe to call.
    let new_handle = unsafe { Owned::new(raw_handle) };

    Ok(new_handle)
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
