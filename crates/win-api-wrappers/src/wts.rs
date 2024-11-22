use super::process::Process;
use super::security::privilege::ScopedPrivileges;
use super::utils::WideString;

use anyhow::anyhow;

use windows::core::Owned;
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_NO_TOKEN, HANDLE};
use windows::Win32::Security::{SE_TCB_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::RemoteDesktop::{
    WTSDomainName, WTSEnumerateSessionsW, WTSFreeMemory, WTSLogoffSession, WTSQuerySessionInformationW,
    WTSQueryUserToken, WTSSendMessageW, WTSUserName, WTSVirtualChannelClose, WTSVirtualChannelOpenEx,
    WTSVirtualChannelQuery, WTSVirtualFileHandle, WTS_CHANNEL_OPTION_DYNAMIC, WTS_CONNECTSTATE_CLASS,
    WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_INFO_CLASS, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;

use crate::ui::MessageBoxResult;
use crate::utils::{AnsiString, SafeWindowsString};

/// RAII wrapper for WTS virtual channel handle.
pub struct WTSVirtualChannel(HANDLE);

impl WTSVirtualChannel {
    /// # Safety
    /// `handle` must be a valid handle returned from `WTSVirtualChannelOpenEx`.
    pub unsafe fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn open_dvc(name: &str) -> anyhow::Result<Self> {
        let channel_name = AnsiString::from(name);

        // SAFETY: Channel name is always a valid pointer to a null-terminated string.
        let raw_wts_handle = unsafe {
            WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, channel_name.as_pcstr(), WTS_CHANNEL_OPTION_DYNAMIC)
        }?;

        // SAFETY: `WTSVirtualChannelOpenEx` always returns a valid handle on success.
        Ok(unsafe { Self::new(raw_wts_handle) })
    }

    pub fn query_file_handle(&self) -> anyhow::Result<Owned<HANDLE>> {
        let mut channel_file_handle_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;

        // SAFETY: It is safe to call `WTSVirtualChannelQuery` with valid channel and
        // destination pointers.
        unsafe {
            WTSVirtualChannelQuery(
                self.0,
                WTSVirtualFileHandle,
                &mut channel_file_handle_ptr as *mut _,
                &mut len,
            )
        }?;

        // SAFETY: `channel_file_handle_ptr` is always a valid pointer to a handle on success.
        let channel_file_handle_ptr = unsafe { WTSMemoryHandle::from_raw(channel_file_handle_ptr) };

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

        // SAFETY: Handle returned from `DuplicateHandle` is always valid if the function succeeds.
        let owned_handle = unsafe { Owned::new(raw_handle) };

        Ok(owned_handle)
    }
}

impl Drop for WTSVirtualChannel {
    fn drop(&mut self) {
        // SAFETY: `Ok` value returned from `WTSVirtualChannelOpenEx` is always a valid handle.
        if let Err(error) = unsafe { WTSVirtualChannelClose(self.0) } {
            error!(%error, "Failed to close WTS virtual channel handle");
        }
    }
}

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WTSConnectState {
    Active = windows::Win32::System::RemoteDesktop::WTSActive.0,
    Connected = windows::Win32::System::RemoteDesktop::WTSConnected.0,
    ConnectQuery = windows::Win32::System::RemoteDesktop::WTSConnectQuery.0,
    Shadow = windows::Win32::System::RemoteDesktop::WTSShadow.0,
    Disconnected = windows::Win32::System::RemoteDesktop::WTSDisconnected.0,
    Idle = windows::Win32::System::RemoteDesktop::WTSIdle.0,
    Listen = windows::Win32::System::RemoteDesktop::WTSListen.0,
    Reset = windows::Win32::System::RemoteDesktop::WTSReset.0,
    Down = windows::Win32::System::RemoteDesktop::WTSDown.0,
    Init = windows::Win32::System::RemoteDesktop::WTSInit.0,
}

impl TryFrom<WTS_CONNECTSTATE_CLASS> for WTSConnectState {
    type Error = anyhow::Error;

    fn try_from(v: WTS_CONNECTSTATE_CLASS) -> Result<Self, Self::Error> {
        match v {
            windows::Win32::System::RemoteDesktop::WTSActive => Ok(WTSConnectState::Active),
            windows::Win32::System::RemoteDesktop::WTSConnected => Ok(WTSConnectState::Connected),
            windows::Win32::System::RemoteDesktop::WTSConnectQuery => Ok(WTSConnectState::ConnectQuery),
            windows::Win32::System::RemoteDesktop::WTSShadow => Ok(WTSConnectState::Shadow),
            windows::Win32::System::RemoteDesktop::WTSDisconnected => Ok(WTSConnectState::Disconnected),
            windows::Win32::System::RemoteDesktop::WTSIdle => Ok(WTSConnectState::Idle),
            windows::Win32::System::RemoteDesktop::WTSListen => Ok(WTSConnectState::Listen),
            windows::Win32::System::RemoteDesktop::WTSReset => Ok(WTSConnectState::Reset),
            windows::Win32::System::RemoteDesktop::WTSDown => Ok(WTSConnectState::Down),
            windows::Win32::System::RemoteDesktop::WTSInit => Ok(WTSConnectState::Init),
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
    /// - The `pWinStationName` pointer needs to be valid for reads up until and including the next `\0`.
    unsafe fn new(wts_session: &WTS_SESSION_INFOW) -> anyhow::Result<Self> {
        Ok(Self {
            session_id: wts_session.SessionId,
            win_station_name: unsafe { wts_session.pWinStationName.to_string()? },
            state: wts_session.State.try_into()?,
        })
    }
}

pub fn get_sessions() -> anyhow::Result<Vec<WTSSessionInfo>> {
    let mut sessions_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut len = 0u32;

    // SAFETY: All buffers are valid.
    unsafe {
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions_ptr, &mut len)?;
    };

    // SAFETY: `sessions_ptr` is always a valid pointer on success.
    // `sessions_ptr` must be freed by `WTSFreeMemory`.
    let sessions_ptr = unsafe { WTSMemory::from_raw(sessions_ptr.cast()) };

    // SAFETY: Verify that all the safety preconditions of from_raw_parts are uphold: https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html#safety
    let sessions_slice: &[WTS_SESSION_INFOW] =
        unsafe { std::slice::from_raw_parts(sessions_ptr.0 as *mut u8 as *mut WTS_SESSION_INFOW, len as usize) };

    let mut sessions = Vec::<WTSSessionInfo>::with_capacity(sessions_slice.len());
    for session in sessions_slice {
        // SAFETY: `session` is valid
        unsafe {
            sessions.push(WTSSessionInfo::new(session)?);
        }
    }

    Ok(sessions)
}

pub fn log_off_session(session_id: u32, wait: bool) -> anyhow::Result<()> {
    // SAFETY: FFI call with no outstanding precondition.
    unsafe { WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, session_id, wait).map_err(|e| e.into()) }
}

pub fn get_session_user_name(session_id: u32) -> anyhow::Result<String> {
    query_session_information_string(session_id, WTSUserName)
}

pub fn get_session_domain_name(session_id: u32) -> anyhow::Result<String> {
    query_session_information_string(session_id, WTSDomainName)
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

    // SAFETY: All buffers are valid.
    // WideString constructed by us and will always have a `Some` value for the underlying buffer.
    // WideString holds a null-terminated UTF-16 string, and as_pcwstr() returns a valid pointer to it.
    unsafe {
        WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            title.as_pcwstr(),
            (title.0.unwrap().len() * size_of_val(&0u16)).try_into()?,
            message.as_pcwstr(),
            (message.0.unwrap().len() * size_of_val(&0u16)).try_into()?,
            windows::Win32::UI::WindowsAndMessaging::MB_SYSTEMMODAL
                | windows::Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND,
            timeout_in_seconds,
            &mut result,
            wait,
        )?
    }

    // NOTE: WTS bug returns IDOK on timeout instead of IDTIMEOUT, if the message style is MB_OK (the default)
    Ok(result.try_into()?)
}

fn query_session_information_string(session_id: u32, info_class: WTS_INFO_CLASS) -> anyhow::Result<String> {
    let mut string_ptr = windows::core::PWSTR::null();
    let mut len: u32 = 0u32;

    matches!(info_class, WTSUserName | WTSDomainName)
        .then(|| 0)
        .ok_or_else(|| anyhow!("info_class is an unsupported WTS_INFO_CLASS: {}", info_class.0))?;

    // SAFETY: All buffers are valid.
    // `string_ptr` must be freed by `WTSFreeMemory`.
    // Passing a `PWSTR` is correct only in the case that `info_class` represents a string result
    unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            info_class,
            &mut string_ptr,
            &mut len,
        )?;
    }

    // SAFETY: `string_ptr` is always a valid pointer on success.
    let _ = unsafe { WTSMemory::from_raw(string_ptr.0.cast()) };

    Ok(string_ptr.to_string_safe()?)
}

/// Returns true if a user is logged in the provided session.
pub fn session_has_logged_in_user(session_id: u32) -> anyhow::Result<bool> {
    let mut current_process_token = Process::current_process().token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    let mut _priv_tcb = ScopedPrivileges::enter(&mut current_process_token, &[SE_TCB_NAME])?;
    let mut handle = HANDLE::default();

    // SAFETY: `WTSQueryUserToken` is safe to call with a valid session id and handle memory ptr.
    match unsafe { WTSQueryUserToken(session_id, &mut handle as *mut _) } {
        Err(err) if err.code() == ERROR_NO_TOKEN.to_hresult() => Ok(false),
        Err(err) => Err(err.into()),
        Ok(()) => {
            // Close handle immediately.
            // SAFETY: `CloseHandle` is safe to call with a valid handle.
            unsafe { CloseHandle(handle).expect("BUG: WTSQueryUserToken should return a valid handle") };
            Ok(true)
        }
    }
}

/// RAII wrapper for WTS memory handle.
struct WTSMemoryHandle {
    inner: WTSMemory,
}

impl WTSMemoryHandle {
    /// Constructs a WTSMemoryHandle from a raw pointer to a handle.
    ///
    /// # Safety
    ///
    /// - `ptr` must be a valid pointer to memory allocated by Remote Desktop Services.
    /// - `ptr` must be a valid pointer to a handle
    /// - `ptr` must be freed by `WTSFreeMemory`.
    unsafe fn from_raw(ptr: *mut core::ffi::c_void) -> Self {
        unsafe {
            Self {
                inner: WTSMemory::from_raw(ptr),
            }
        }
    }

    fn as_handle(&self) -> HANDLE {
        if self.inner.0.is_null() {
            return HANDLE::default();
        }

        // SAFETY: `self.0` is always a valid pointer to a handle if constructed properly,
        // therefore it is safe to dereference it.
        HANDLE(unsafe { *(self.inner.0 as *mut *mut std::ffi::c_void) })
    }
}

impl Default for WTSMemoryHandle {
    fn default() -> Self {
        unsafe { Self::from_raw(std::ptr::null_mut()) }
    }
}

/// RAII wrapper for WTS memory.
struct WTSMemory(*mut core::ffi::c_void);

impl WTSMemory {
    /// Constructs a WTSMemory from a raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must be a valid pointer to memory allocated by Remote Desktop Services.
    /// - `ptr` must be freed by `WTSFreeMemory`.
    unsafe fn from_raw(ptr: *mut core::ffi::c_void) -> Self {
        Self(ptr)
    }
}

impl Drop for WTSMemory {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }

        // SAFETY: FFI call with no outstanding precondition.
        unsafe { WTSFreeMemory(self.0) }
    }
}

impl Default for WTSMemory {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
}
