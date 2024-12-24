use windows::core::Owned;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GENERIC_READ};
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatus, StartServiceW, QUERY_SERVICE_CONFIGW,
    SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START,
    SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
    SERVICE_SYSTEM_START,
};

use crate::utils::WideString;
use crate::Error;

pub struct ServiceManager {
    handle: Owned<SC_HANDLE>,
}

impl ServiceManager {
    pub fn open_read() -> Result<Self, Error> {
        Self::open_with_access(GENERIC_READ.0)
    }

    pub fn open_all_access() -> Result<Self, Error> {
        Self::open_with_access(SC_MANAGER_ALL_ACCESS)
    }

    fn open_with_access(access: u32) -> Result<Self, Error> {
        // SAFETY: No preconditions.
        let raw_sc_handle = unsafe { OpenSCManagerW(None, None, access)? };

        // SAFETY: No preconditions.
        let handle = unsafe { Owned::new(raw_sc_handle) };

        Ok(Self { handle })
    }

    fn open_service_with_access(&self, service_name: &str, access: u32) -> Result<Service, Error> {
        let service_name_wide = WideString::from(service_name);

        // SAFETY: No preconditions.
        let raw_service_handle = unsafe { OpenServiceW(*self.handle, service_name_wide.as_pcwstr(), access)? };

        // SAFETY: No preconditions.
        let handle = unsafe { Owned::new(raw_service_handle) };

        Ok(Service { handle })
    }

    pub fn open_service_read(&self, service_name: &str) -> Result<Service, Error> {
        self.open_service_with_access(service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)
    }

    pub fn open_service_all_access(&self, service_name: &str) -> Result<Service, Error> {
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
    pub fn startup_mode(&self) -> Result<ServiceStartupMode, Error> {
        let mut cbbufsize = 0u32;
        let mut pcbbytesneeded = 0u32;

        // SAFETY: No preconditions. Query required buffer size.
        let result = unsafe { QueryServiceConfigW(*self.handle, None, 0, &mut pcbbytesneeded) };

        match result {
            Err(err) if err.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {
                // Expected error, continue.
            }
            Err(err) => return Err(err.into()),
            Ok(_) => panic!("QueryServiceConfigW should fail with ERROR_INSUFFICIENT_BUFFER"),
        }

        // Event though `QueryServiceConfigW` states that `lpserviceconfig` is a `buffer`,
        // it needs to be aligned ir order to avoid undefined behavior when accessing
        // `QUERY_SERVICE_CONFIGW.
        //
        // Clippy warning:
        // casting from `*mut u8` to a more-strictly-aligned pointer
        // (`*mut windows::Win32::System::Services::QUERY_SERVICE_CONFIGW`) (1 < 8 bytes)
        assert_eq!(align_of::<QUERY_SERVICE_CONFIGW>(), size_of::<u64>());

        let pcbbytesneeded_usize = usize::try_from(pcbbytesneeded).expect("pcbbytesneeded < 8K as per MSDN");

        let aligned_u64_array_size =
            pcbbytesneeded_usize / size_of::<u64>() + usize::from(pcbbytesneeded_usize % size_of::<u64>() != 0);

        let aligned_size = u32::try_from(aligned_u64_array_size * size_of::<u64>()).expect("pcbbytesneeded <= 8K");

        let mut buffer: Box<Vec<u64>> = Box::new(vec![0; aligned_u64_array_size]);

        // SAFETY: Buffuer with correct size was allocated prior to the call.
        unsafe {
            QueryServiceConfigW(
                *self.handle,
                Some(buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
                aligned_size,
                &mut cbbufsize,
            )?
        };

        let ptr = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        // SAFETY: `QueryServiceConfigW` succeeded, thus `lpserviceconfig` is valid and contains
        // QUERY_SERVICE_CONFIGW structure.
        let config = unsafe { &*ptr };

        match config.dwStartType {
            SERVICE_BOOT_START => Ok(ServiceStartupMode::Boot),
            SERVICE_SYSTEM_START => Ok(ServiceStartupMode::System),
            SERVICE_AUTO_START => Ok(ServiceStartupMode::Automatic),
            SERVICE_DEMAND_START => Ok(ServiceStartupMode::Manual),
            SERVICE_DISABLED => Ok(ServiceStartupMode::Disabled),
            _ => panic!("WinAPI returned invalid service startup mode"),
        }
    }

    pub fn is_running(&self) -> Result<bool, Error> {
        let mut service_status = SERVICE_STATUS::default();
        unsafe { QueryServiceStatus(*self.handle, &mut service_status as *mut _)? };

        Ok(service_status.dwCurrentState == SERVICE_RUNNING)
    }

    pub fn start(&self) -> Result<(), Error> {
        // SAFETY: No preconditions, arguments are not used.
        unsafe { StartServiceW(*self.handle, None)? };

        Ok(())
    }
}
