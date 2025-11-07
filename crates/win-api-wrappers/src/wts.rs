use anyhow::anyhow;
use tracing::error;
use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_TOKEN, HANDLE};
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::RemoteDesktop::{
    self, WTS_CHANNEL_OPTION_DYNAMIC, WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
    WTS_INFO_CLASS, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory, WTSLogoffSession,
    WTSQuerySessionInformationW, WTSQueryUserToken, WTSSendMessageW, WTSVirtualChannelClose, WTSVirtualChannelOpenEx,
    WTSVirtualChannelQuery, WTSVirtualFileHandle,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;
use windows::core::Owned;

use crate::process::Process;
use crate::security::privilege::{self, ScopedPrivileges};
use crate::ui::MessageBoxResult;
use crate::utils::{AnsiString, SafeWindowsString, WideString};

/// RAII wrapper for WTS virtual channel handle.
pub struct WtsVirtualChannel(HANDLE);

impl WtsVirtualChannel {
    /// # Safety
    ///
    /// `handle` must be a valid handle returned by `WTSVirtualChannelOpenEx`.
    unsafe fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn open_dvc(name: &str) -> anyhow::Result<Self> {
        let channel_name = AnsiString::from(name);

        // SAFETY: `channel_name.as_pcstr()` is always a valid pointer to a null-terminated string.
        let wts_handle = unsafe {
            WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, channel_name.as_pcstr(), WTS_CHANNEL_OPTION_DYNAMIC)?
        };

        // SAFETY: `WTSVirtualChannelOpenEx` always returns a valid handle on success.
        let channel = unsafe { Self::new(wts_handle) };

        Ok(channel)
    }

    pub fn query_file_handle(&self) -> anyhow::Result<Owned<HANDLE>> {
        let mut channel_file_handle = core::ptr::null_mut();
        let mut len: u32 = 0;

        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            WTSVirtualChannelQuery(self.0, WTSVirtualFileHandle, &mut channel_file_handle, &mut len)?;
        }

        if len != u32::try_from(size_of::<HANDLE>()).expect("HANDLE always fits into u32") {
            anyhow::bail!("WTSVirtualChannelQuery (WTSVirtualFileHandle) returned something unexpected");
        }

        // SAFETY: On success, `WTSVirtualChannelQuery` sets a pointer to a HANDLE which must be freed with `WTSFreeMemory`.
        let channel_file_handle = unsafe { WtsMemory::from_raw(channel_file_handle.cast::<HANDLE>()) };

        // SAFETY: `WTSVirtualChannelQuery` called with `WTSVirtualFileHandle` virtual class will always place a pointer to a HANDLE.
        let channel_file_handle = unsafe { *channel_file_handle.as_ptr() };

        // SAFETY: FFI call with no outstanding precondition.
        let current_process = unsafe { GetCurrentProcess() };

        let mut duplicated_handle = HANDLE::default();

        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            DuplicateHandle(
                current_process,
                channel_file_handle,
                current_process,
                &mut duplicated_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
        }

        // SAFETY: Handle returned by `DuplicateHandle` on success is always valid and owned.
        let duplicated_handle = unsafe { Owned::new(duplicated_handle) };

        Ok(duplicated_handle)
    }
}

impl Drop for WtsVirtualChannel {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid handle per construction.
        if let Err(error) = unsafe { WTSVirtualChannelClose(self.0) } {
            error!(%error, "Failed to close WTS virtual channel handle");
        }
    }
}

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WTSConnectState {
    Active = RemoteDesktop::WTSActive.0,
    Connected = RemoteDesktop::WTSConnected.0,
    ConnectQuery = RemoteDesktop::WTSConnectQuery.0,
    Shadow = RemoteDesktop::WTSShadow.0,
    Disconnected = RemoteDesktop::WTSDisconnected.0,
    Idle = RemoteDesktop::WTSIdle.0,
    Listen = RemoteDesktop::WTSListen.0,
    Reset = RemoteDesktop::WTSReset.0,
    Down = RemoteDesktop::WTSDown.0,
    Init = RemoteDesktop::WTSInit.0,
}

impl TryFrom<WTS_CONNECTSTATE_CLASS> for WTSConnectState {
    type Error = anyhow::Error;

    fn try_from(v: WTS_CONNECTSTATE_CLASS) -> Result<Self, Self::Error> {
        match v {
            RemoteDesktop::WTSActive => Ok(WTSConnectState::Active),
            RemoteDesktop::WTSConnected => Ok(WTSConnectState::Connected),
            RemoteDesktop::WTSConnectQuery => Ok(WTSConnectState::ConnectQuery),
            RemoteDesktop::WTSShadow => Ok(WTSConnectState::Shadow),
            RemoteDesktop::WTSDisconnected => Ok(WTSConnectState::Disconnected),
            RemoteDesktop::WTSIdle => Ok(WTSConnectState::Idle),
            RemoteDesktop::WTSListen => Ok(WTSConnectState::Listen),
            RemoteDesktop::WTSReset => Ok(WTSConnectState::Reset),
            RemoteDesktop::WTSDown => Ok(WTSConnectState::Down),
            RemoteDesktop::WTSInit => Ok(WTSConnectState::Init),
            _ => Err(anyhow::anyhow!("Invalid WTS_CONNECTSTATE_CLASS: {}", v.0)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WTSSessionInfo {
    pub session_id: u32,
    pub win_station_name: String,
    pub state: WTSConnectState,
}

impl WTSSessionInfo {
    /// # Safety
    ///
    /// - The `wts_session.pWinStationName` pointer must be valid for reads up until and including the next `\0`.
    unsafe fn new(wts_session: &WTS_SESSION_INFOW) -> anyhow::Result<Self> {
        // SAFETY: Same preconditions as the current function.
        let win_station_name = unsafe { wts_session.pWinStationName.to_string()? };

        Ok(Self {
            session_id: wts_session.SessionId,
            win_station_name,
            state: wts_session.State.try_into()?,
        })
    }
}

pub fn get_sessions() -> anyhow::Result<Vec<WTSSessionInfo>> {
    let mut sessions: *mut WTS_SESSION_INFOW = core::ptr::null_mut();
    let mut count = 0u32;

    // SAFETY: FFI call with no outstanding precondition.
    unsafe {
        WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut sessions, &mut count)?;
    };

    // SAFETY: The pointer placed into `sessions` by `WTSEnumerateSessionsW` must be freed by `WTSFreeMemory`.
    let sessions = unsafe { WtsMemory::from_raw(sessions) };

    // SAFETY:
    // - `WTSEnumerateSessionsW` returns a pointer valid for `count` reads of `WTS_SESSION_INFOW`.
    // - `WTSEnumerateSessionsW` is also returning a pointer properly aligned.
    // - We ensure the memory referenced by the slice is not mutated by shadowing the variable.
    // - There are never so many sessions that `count * mem::size_of::<WTS_SESSION_INFOW>()` overflows `isize`.
    let sessions = unsafe { sessions.cast_slice(count as usize) };

    let sessions = sessions
        .iter()
        .map(|session| {
            // SAFETY: `session` is a `WTS_SESSION_INFOW` initialized by `WTSEnumerateSessionsW` that we trust to be valid.
            unsafe { WTSSessionInfo::new(session) }
        })
        .collect::<Result<Vec<WTSSessionInfo>, _>>()?;

    Ok(sessions)
}

pub fn log_off_session(session_id: u32, wait: bool) -> anyhow::Result<()> {
    // SAFETY: FFI call with no outstanding precondition.
    unsafe { WTSLogoffSession(Some(WTS_CURRENT_SERVER_HANDLE), session_id, wait).map_err(|e| e.into()) }
}

pub fn get_session_user_name(session_id: u32) -> anyhow::Result<String> {
    query_session_information_string(session_id, RemoteDesktop::WTSUserName)
}

pub fn get_session_domain_name(session_id: u32) -> anyhow::Result<String> {
    query_session_information_string(session_id, RemoteDesktop::WTSDomainName)
}

pub fn send_message_to_session(
    session_id: u32,
    title: &str,
    message: &str,
    wait: bool,
    timeout_in_seconds: u32,
) -> anyhow::Result<MessageBoxResult> {
    let title = WideString::from(title);
    let message = WideString::from(message);
    let mut result: MESSAGEBOX_RESULT = MESSAGEBOX_RESULT::default();

    // FIXME: This is not a safety description + migrate away from WideString.

    // SAFETY:
    // - `title` and `message` constructed by us and will always have a `Some` value for the underlying buffer.
    // - `title` and `message` are holding a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    unsafe {
        WTSSendMessageW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            title.as_pcwstr(),
            (title.0.expect("title buffer is always Some").len() * size_of_val(&0u16)).try_into()?,
            message.as_pcwstr(),
            (message.0.expect("message buffer is always Some").len() * size_of_val(&0u16)).try_into()?,
            windows::Win32::UI::WindowsAndMessaging::MB_SYSTEMMODAL
                | windows::Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND,
            timeout_in_seconds,
            &mut result,
            wait,
        )?
    }

    // NOTE: WTS bug returns IDOK on timeout instead of IDTIMEOUT, if the message style is MB_OK (the default)
    result.try_into()
}

fn query_session_information_string(session_id: u32, info_class: WTS_INFO_CLASS) -> anyhow::Result<String> {
    use windows::core::PWSTR;

    let mut string = PWSTR::null();
    let mut len: u32 = 0u32;

    matches!(info_class, RemoteDesktop::WTSUserName | RemoteDesktop::WTSDomainName)
        .then(|| 0)
        .ok_or_else(|| anyhow!("info_class is an unsupported WTS_INFO_CLASS: {}", info_class.0))?;

    // SAFETY: Passing a `PWSTR` is correct in the case where `info_class` represents a string result.
    unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            info_class,
            &mut string,
            &mut len,
        )?;
    }

    // SAFETY: On success, WTSQuerySessionInformationW places a valid pointer which must be freed by `WTSFreeMemory`.
    let _guard = unsafe { WtsMemory::from_raw(string.as_ptr()) };

    let string = string.to_string_safe()?;

    Ok(string)
}

/// Returns true if a user is logged in the provided session.
pub fn session_has_logged_in_user(session_id: u32) -> anyhow::Result<bool> {
    let mut current_process_token = Process::current_process().token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    let mut _priv_tcb = ScopedPrivileges::enter(&mut current_process_token, &[privilege::SE_TCB_NAME])?;
    let mut handle = HANDLE::default();

    // SAFETY: FFI call with no outstanding precondition.
    let res = unsafe { WTSQueryUserToken(session_id, &mut handle) };

    match res {
        Ok(()) => {
            // Close handle immediately.

            // SAFETY: On success, `handle` is a valid handle to an open object.
            unsafe { CloseHandle(handle).expect("BUG: WTSQueryUserToken should return a valid handle") };

            Ok(true)
        }
        Err(err) if err.code() == ERROR_NO_TOKEN.to_hresult() => Ok(false),
        Err(err) => Err(err.into()),
    }
}

struct WtsFreeMemory;

impl crate::memory::FreeMemory for WtsFreeMemory {
    /// # Safety
    ///
    /// `ptr` is a pointer which must be freed by `WTSFreeMemory`
    unsafe fn free(ptr: *mut core::ffi::c_void) {
        // SAFETY: Per invariant on `ptr`, WTSFreeMemory must be called on it for releasing the memory.
        unsafe { WTSFreeMemory(ptr) };
    }
}

type WtsMemory<T = core::ffi::c_void> = crate::memory::MemoryWrapper<WtsFreeMemory, T>;
