use std::ffi::c_void;
use std::ptr::{self, NonNull};
use std::slice;

use windows::Win32::Foundation::{E_INVALIDARG, ERROR_MORE_DATA};
use windows::Win32::Security::{SecurityIdentification, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TokenPrimary};
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Rpc::{
    MIDL_SERVER_INFO, RPC_BINDING_VECTOR, RPC_CALL_ATTRIBUTES_V2_W, RPC_CALL_ATTRIBUTES_VERSION, RPC_QUERY_CLIENT_PID,
    RPC_QUERY_CLIENT_PRINCIPAL_NAME, RPC_QUERY_SERVER_PRINCIPAL_NAME, RPC_SERVER_INTERFACE, RpcBindingVectorFree,
    RpcImpersonateClient, RpcRevertToSelfEx, RpcServerInqBindings, RpcServerInqCallAttributesW, SERVER_ROUTINE,
};
use windows::core::GUID;

use crate::Error;
use crate::thread::Thread;
use crate::token::Token;
use crate::utils::set_memory_protection;

use anyhow::{Result, bail};

#[expect(non_camel_case_types)] // Unless a better name is found…
pub type RPC_BINDING_HANDLE = *mut c_void;

// FIXME: unsound API. E.g.: it’s possible to build a RpcBindingHandle with a dangling pointer,
// and to call safe functions unsafely dereferencing that pointer.
pub struct RpcBindingHandle(pub RPC_BINDING_HANDLE);

pub struct RpcCallAttributes {
    pub client_pid: u32,
    pub server_principal_name: String,
    pub client_principal_name: String,
}

impl RpcBindingHandle {
    pub fn inquire_caller(&self) -> Result<RpcCallAttributes> {
        let mut client_principal_name = Vec::new();
        let mut server_principal_name = Vec::new();

        let mut attribs = RPC_CALL_ATTRIBUTES_V2_W {
            Version: RPC_CALL_ATTRIBUTES_VERSION,
            Flags: RPC_QUERY_SERVER_PRINCIPAL_NAME | RPC_QUERY_CLIENT_PRINCIPAL_NAME | RPC_QUERY_CLIENT_PID,
            ..Default::default()
        };

        // SAFETY: No preconditions.
        let status = unsafe { RpcServerInqCallAttributesW(Some(self.0), &mut attribs as *mut _ as *mut c_void) };

        if status.to_hresult() != ERROR_MORE_DATA.to_hresult() {
            bail!(Error::from(status));
        }

        client_principal_name.resize((attribs.ClientPrincipalNameBufferLength / 2) as usize, 0);
        server_principal_name.resize((attribs.ServerPrincipalNameBufferLength / 2) as usize, 0);

        attribs.ClientPrincipalName = client_principal_name.as_mut_ptr();
        attribs.ClientPrincipalNameBufferLength = (client_principal_name.len() * size_of::<u16>()).try_into()?;
        attribs.ServerPrincipalName = server_principal_name.as_mut_ptr();
        attribs.ServerPrincipalNameBufferLength = (server_principal_name.len() * size_of::<u16>()).try_into()?;

        // SAFETY: No preconditions.
        let status = unsafe { RpcServerInqCallAttributesW(Some(self.0), &mut attribs as *mut _ as *mut c_void) };

        status.ok()?;

        // Remove trailing null byte
        client_principal_name.pop();
        server_principal_name.pop();

        Ok(RpcCallAttributes {
            client_pid: u32::try_from(attribs.ClientPID.0 as usize)?,
            client_principal_name: String::from_utf16(&client_principal_name).map_err(windows::core::Error::from)?,
            server_principal_name: String::from_utf16(&server_principal_name).map_err(windows::core::Error::from)?,
        })
    }

    pub fn impersonate_client(&self) -> Result<RpcBindingImpersonation<'_>> {
        RpcBindingImpersonation::try_new(self)
    }

    pub fn client_primary_token(&self) -> Result<Token> {
        let _ctx = self.impersonate_client()?;

        Thread::current().token(TOKEN_ALL_ACCESS, true)?.duplicate(
            TOKEN_ACCESS_MASK(0),
            None,
            SecurityIdentification,
            TokenPrimary,
        )
    }
}

pub struct RpcBindingImpersonation<'a> {
    handle: &'a RpcBindingHandle,
}

impl<'a> RpcBindingImpersonation<'a> {
    fn try_new(handle: &'a RpcBindingHandle) -> Result<Self> {
        // SAFETY: Caller should have `SeImpersonatePrivilege` to impersonate beyond identification.
        // Must be reverted by `RpcRevertToSelfEx` in multithreaded applications.
        unsafe { RpcImpersonateClient(Some(handle.0)) }.ok()?;

        Ok(Self { handle })
    }
}

impl Drop for RpcBindingImpersonation<'_> {
    fn drop(&mut self) {
        // SAFETY: No preconditions. Panic on fail as thread will remain in client context.
        unsafe { RpcRevertToSelfEx(Some(self.handle.0)) }
            .ok()
            .expect("RpcRevertToSelfEx failed")
    }
}

#[derive(Clone, Copy)]
pub struct RpcServerInterfacePointer {
    pub raw: &'static RPC_SERVER_INTERFACE,
}

// SAFETY: RpcServerInterfacePointer only contains a static reference, which is safe to send across threads.
unsafe impl Send for RpcServerInterfacePointer {}

impl RpcServerInterfacePointer {
    pub fn handler_cnt(&self) -> Result<usize> {
        let dispatch_table =
            // SAFETY: We assume `DispatchTable` points to a valid `RPC_DISPATCH_TABLE` if non null.
            unsafe { self.raw.DispatchTable.as_ref() }.ok_or_else(|| Error::NullPointer("RPC_DISPATCH_TABLE"))?;

        Ok(dispatch_table.DispatchTableCount as usize)
    }

    pub fn handlers(&self) -> Result<Box<[SERVER_ROUTINE]>> {
        let handler_cnt = self.handler_cnt()?;
        let server_info = self.server_info()?;

        let raw_dispatch_table = server_info.DispatchTable;

        let mut handlers = Vec::with_capacity(handler_cnt);

        for i in 0..handler_cnt {
            // SAFETY: We assume `DispatchTable` and `DispatchTableCount` are truthful.
            let raw = unsafe { raw_dispatch_table.add(i) };

            // SAFETY: We assume that `DispatchTable` has actual function pointers under it.
            let raw = unsafe { raw.as_ref() }.ok_or_else(|| Error::NullPointer("DispatchTable entry"))?;

            handlers.push(*raw);
        }

        Ok(handlers.into_boxed_slice())
    }

    pub fn set_handlers(&mut self, handlers: &[SERVER_ROUTINE]) -> Result<()> {
        if handlers.len() != self.handler_cnt()? {
            bail!(Error::from_hresult(E_INVALIDARG));
        }

        let server_info = self.server_info()?;

        let raw_dispatch_table = server_info.DispatchTable;

        for (i, new_handler) in handlers.iter().enumerate() {
            // SAFETY: Assume structure is truthful and has correct number of handlers.
            let addr = unsafe { raw_dispatch_table.add(i) }.cast_mut();

            // SAFETY: Assume the address points to a valid handler which is not currently in use.
            let old_prot = unsafe { set_memory_protection(addr.cast(), size_of::<*const ()>(), PAGE_READWRITE) }?;

            // TODO: See if it could be possible to freeze other threads during switch or to do an atomic switch.
            // SAFETY: Because of previous assumption and memory protection, this should succeed.
            unsafe { *addr = *new_handler };

            // SAFETY: Address is already assumed to be valid.
            let _ = unsafe { set_memory_protection(addr.cast(), size_of::<*const ()>(), old_prot) }?;
        }

        Ok(())
    }

    fn server_info(&self) -> Result<&'static MIDL_SERVER_INFO> {
        // SAFETY: We assume `self.raw.InterpreterInfo` is a valid `MIDL_SERVER_INFO` if non null.
        Ok(unsafe {
            self.raw
                .InterpreterInfo
                .cast::<MIDL_SERVER_INFO>()
                .as_ref()
                .ok_or_else(|| Error::NullPointer("MIDL_SERVER_INFO"))
        }?)
    }

    pub fn id(&self) -> GUID {
        self.raw.InterfaceId.SyntaxGUID
    }
}

pub struct RpcBindingVector {
    raw: NonNull<RPC_BINDING_VECTOR>,
}

impl RpcBindingVector {
    pub fn try_inquire_server() -> Result<Self> {
        let mut raw = ptr::null_mut();

        // SAFETY: No preconditions. Must be freed with `RpcBindingVectorFree`.
        let status = unsafe { RpcServerInqBindings(&mut raw) };

        status.ok()?;

        Ok(RpcBindingVector {
            // SAFETY: Assume `raw` is non NULL if `RpcServerInqBindings` is successful.
            raw: unsafe { NonNull::new_unchecked(raw) },
        })
    }

    pub fn as_slice(&self) -> &[RPC_BINDING_HANDLE] {
        // SAFETY: Assume `self.raw` points to a valid `RPC_BINDING_VECTOR`.
        let deref = unsafe { self.raw.as_ref() };

        // SAFETY: `deref.BindingH` is non NULL since it is the first element of the VLA.
        // Assume the structure is truthful.
        unsafe {
            slice::from_raw_parts(
                deref.BindingH.as_ptr().cast::<RPC_BINDING_HANDLE>(),
                deref.Count as usize,
            )
        }
    }
}

impl Drop for RpcBindingVector {
    fn drop(&mut self) {
        // SAFETY: No preconditions.
        let _ = unsafe { RpcBindingVectorFree(&mut self.raw.as_ptr()) };
    }
}
