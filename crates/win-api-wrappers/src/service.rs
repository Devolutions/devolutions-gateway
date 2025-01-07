use std::alloc::Layout;

use windows::core::Owned;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GENERIC_READ};
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus, StartServiceW, QUERY_SERVICE_CONFIGW,
    SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START,
    SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
    SERVICE_SYSTEM_START,
};

use crate::raw_buffer::RawBuffer;
use crate::utils::WideString;

pub struct ServiceManager {
    handle: Owned<SC_HANDLE>,
}

impl ServiceManager {
    pub fn open_read() -> anyhow::Result<Self> {
        Self::open_with_access(GENERIC_READ.0)
    }

    pub fn open_all_access() -> anyhow::Result<Self> {
        Self::open_with_access(SC_MANAGER_ALL_ACCESS)
    }

    fn open_with_access(access: u32) -> anyhow::Result<Self> {
        // SAFETY: FFI call with no outstanding preconditions.
        let raw_sc_handle = unsafe { OpenSCManagerW(None, None, access)? };

        // SAFETY: On success, the handle returned by `OpenSCManagerW` is valid and owned by the
        // caller.
        let handle = unsafe { Owned::new(raw_sc_handle) };

        Ok(Self { handle })
    }

    fn open_service_with_access(&self, service_name: &str, access: u32) -> anyhow::Result<Service> {
        let service_name = WideString::from(service_name);

        // SAFETY:
        // - Value passed as hSCManager is valid as long as `ServiceManager` instance is alive.
        // - service_name_wide is a valid, null-terminated UTF-16 string allocated on the heap.
        let raw_service_handle = unsafe { OpenServiceW(*self.handle, service_name.as_pcwstr(), access)? };

        // SAFETY: Handle returned by `OpenServiceW` is valid and needs to be closed after use,
        // thus it is safe to take ownership of it via `Owned`.
        let handle = unsafe { Owned::new(raw_service_handle) };

        Ok(Service { handle })
    }

    pub fn open_service_read(&self, service_name: &str) -> anyhow::Result<Service> {
        self.open_service_with_access(service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)
    }

    pub fn open_service_all_access(&self, service_name: &str) -> anyhow::Result<Service> {
        self.open_service_with_access(service_name, SERVICE_ALL_ACCESS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStartupMode {
    Boot,
    System,
    Automatic,
    Manual,
    Disabled,
}

pub struct Service {
    handle: Owned<SC_HANDLE>,
}

impl Service {
    pub fn startup_mode(&self) -> anyhow::Result<ServiceStartupMode> {
        let mut cbbufsize = 0u32;
        let mut pcbbytesneeded = 0u32;

        // SAFETY: FFI call with no outstanding preconditions.
        let result = unsafe { QueryServiceConfigW(*self.handle, None, 0, &mut pcbbytesneeded) };

        match result {
            Err(err) if err.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {
                // Expected error, continue.
            }
            Err(err) => return Err(err.into()),
            Ok(_) => panic!("QueryServiceConfigW should fail with ERROR_INSUFFICIENT_BUFFER"),
        }

        // The most typical buffer we work with in Rust are homogeneous arrays of integers such
        // as [u8] or Vec<u8>, but in Microsoft’s Win32 documentation, a `buffer` generally refers
        // to a caller-allocated memory region that an API uses to either input or output data, and
        // it is ultimately coerced into some other type with various alignment requirements.
        //
        // lpServiceConfig should point to aligned buffer that could hold a QUERY_SERVICE_CONFIGW
        // structure.
        let layout = Layout::from_size_align(
            usize::try_from(pcbbytesneeded).expect("pcbbytesneeded < 8K as per MSDN"),
            align_of::<QUERY_SERVICE_CONFIGW>(),
        )?;

        // SAFETY: The layout initialization is checked using the Layout::from_size_align method.
        let mut buffer = unsafe { RawBuffer::alloc_zeroed(layout)? };

        // SAFETY: Buffer passed to `lpServiceConfig` have enough size to hold a
        // QUERY_SERVICE_CONFIGW structure, as required size was queried and allocated above.
        // Passed buffer have correct alignment to hold QUERY_SERVICE_CONFIGW structure.
        unsafe {
            // Pointer cast is valid, as `buffer` is allocated with correct alignment above.
            #[expect(clippy::cast_ptr_alignment)]
            QueryServiceConfigW(
                *self.handle,
                Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                pcbbytesneeded,
                &mut cbbufsize,
            )?
        };

        // SAFETY: `QueryServiceConfigW` succeeded, thus `lpserviceconfig` is valid and contains
        // a QUERY_SERVICE_CONFIGW structure.
        let config = unsafe { buffer.as_ref_cast::<QUERY_SERVICE_CONFIGW>() };

        match config.dwStartType {
            SERVICE_BOOT_START => Ok(ServiceStartupMode::Boot),
            SERVICE_SYSTEM_START => Ok(ServiceStartupMode::System),
            SERVICE_AUTO_START => Ok(ServiceStartupMode::Automatic),
            SERVICE_DEMAND_START => Ok(ServiceStartupMode::Manual),
            SERVICE_DISABLED => Ok(ServiceStartupMode::Disabled),
            _ => panic!("WinAPI returned invalid service startup mode"),
        }
    }

    pub fn is_running(&self) -> anyhow::Result<bool> {
        let mut service_status = SERVICE_STATUS::default();

        // SAFETY: hService is a valid handle.
        // lpServiceStatus is a valid pointer to a stack-allocated SERVICE_STATUS structure.
        unsafe { QueryServiceStatus(*self.handle, &mut service_status as *mut _)? };

        Ok(service_status.dwCurrentState == SERVICE_RUNNING)
    }

    pub fn start(&self) -> anyhow::Result<()> {
        // SAFETY: FFI call with no outstanding preconditions.
        unsafe { StartServiceW(*self.handle, None)? };

        Ok(())
    }
}
