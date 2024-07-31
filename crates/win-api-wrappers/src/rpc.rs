use std::{
    ffi::c_void,
    mem,
    ptr::{self, NonNull},
    slice,
};

use windows::{
    core::GUID,
    Win32::{
        Foundation::{ERROR_MORE_DATA, E_INVALIDARG, E_POINTER},
        Security::{SecurityIdentification, TokenPrimary, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS},
        System::{
            Memory::PAGE_READWRITE,
            Rpc::{
                RpcBindingVectorFree, RpcImpersonateClient, RpcRevertToSelfEx, RpcServerInqBindings,
                RpcServerInqCallAttributesW, MIDL_SERVER_INFO, RPC_BINDING_VECTOR, RPC_CALL_ATTRIBUTES_V2_W,
                RPC_CALL_ATTRIBUTES_VERSION, RPC_QUERY_CLIENT_PID, RPC_QUERY_CLIENT_PRINCIPAL_NAME,
                RPC_QUERY_SERVER_PRINCIPAL_NAME, RPC_SERVER_INTERFACE, SERVER_ROUTINE,
            },
        },
    },
};

use crate::win::set_memory_protection;
use crate::{
    error::Error,
    win::{Thread, Token},
};

use anyhow::{bail, Result};

#[allow(non_camel_case_types)]
pub type RPC_BINDING_HANDLE = *mut c_void;

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

        let mut attribs = RPC_CALL_ATTRIBUTES_V2_W::default();
        attribs.Version = RPC_CALL_ATTRIBUTES_VERSION;
        attribs.Flags = RPC_QUERY_SERVER_PRINCIPAL_NAME | RPC_QUERY_CLIENT_PRINCIPAL_NAME | RPC_QUERY_CLIENT_PID;
        let status = unsafe { RpcServerInqCallAttributesW(Some(self.0), &mut attribs as *mut _ as _) };

        if status.0 != ERROR_MORE_DATA.0 as i32 {
            bail!(Error::from(status));
        }

        client_principal_name.resize((attribs.ClientPrincipalNameBufferLength / 2) as _, 0);
        server_principal_name.resize((attribs.ServerPrincipalNameBufferLength / 2) as _, 0);

        attribs.ClientPrincipalName = client_principal_name.as_mut_ptr();
        attribs.ClientPrincipalNameBufferLength = (client_principal_name.len() * mem::size_of::<u16>()) as _;
        attribs.ServerPrincipalName = server_principal_name.as_mut_ptr();
        attribs.ServerPrincipalNameBufferLength = (server_principal_name.len() * mem::size_of::<u16>()) as _;

        let status = unsafe { RpcServerInqCallAttributesW(Some(self.0), &mut attribs as *mut _ as _) };

        status.ok()?;

        // Remove trailing null byte
        client_principal_name.pop();
        server_principal_name.pop();

        Ok(RpcCallAttributes {
            client_pid: attribs.ClientPID.0 as _,
            client_principal_name: String::from_utf16(&client_principal_name)
                .map_err(|e| windows::core::Error::from(e))?,
            server_principal_name: String::from_utf16(&server_principal_name)
                .map_err(|e| windows::core::Error::from(e))?,
        })
    }

    pub fn impersonate_client<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        unsafe { RpcImpersonateClient(Some(self.0)) }.ok()?;

        let r = f();

        unsafe { RpcRevertToSelfEx(Some(self.0)) }.ok()?;

        r
    }

    pub fn client_primary_token(&self) -> Result<Token> {
        let mut token = None;

        self.impersonate_client(|| {
            token = Some(Thread::current().token(TOKEN_ALL_ACCESS, true)?.duplicate(
                TOKEN_ACCESS_MASK(0),
                None,
                SecurityIdentification,
                TokenPrimary,
            )?);

            Ok(())
        })?;

        Ok(token.unwrap())
    }
}

#[derive(Clone, Copy)]
pub struct RpcServerInterfacePointer {
    pub raw: NonNull<RPC_SERVER_INTERFACE>,
}

unsafe impl Send for RpcServerInterfacePointer {}

impl RpcServerInterfacePointer {
    pub fn handler_cnt(&self) -> Result<usize> {
        let dispatch_table =
            NonNull::new(unsafe { self.raw.as_ref() }.DispatchTable).ok_or_else(|| Error::from_hresult(E_POINTER))?;

        Ok(unsafe { dispatch_table.as_ref() }.DispatchTableCount as _)
    }

    pub fn handlers(&self) -> Result<Box<[SERVER_ROUTINE]>> {
        let handler_cnt = self.handler_cnt()?;
        let server_info = self.server_info()?;

        let raw_dispatch_table = unsafe { server_info.as_ref() }.DispatchTable;

        let mut handlers = Vec::with_capacity(handler_cnt);

        for i in 0..handler_cnt {
            let raw = unsafe { *raw_dispatch_table.add(i) };
            handlers.push(raw);
        }

        Ok(handlers.into_boxed_slice())
    }

    pub fn set_handlers(&mut self, handlers: &[SERVER_ROUTINE]) -> Result<()> {
        if handlers.len() != self.handler_cnt()? {
            bail!(Error::from_hresult(E_INVALIDARG));
        }

        let mut server_info = self.server_info()?;

        let raw_dispatch_table = unsafe { server_info.as_mut() }.DispatchTable;

        for i in 0..handlers.len() {
            unsafe {
                let addr = raw_dispatch_table.add(i).cast_mut();
                let old_prot = set_memory_protection(addr as _, mem::size_of::<*const ()>(), PAGE_READWRITE)?;

                *addr = handlers[i];

                let _ = set_memory_protection(addr as _, mem::size_of::<*const ()>(), old_prot)?;
            }
        }

        Ok(())
    }

    fn server_info(&self) -> Result<NonNull<MIDL_SERVER_INFO>> {
        Ok(NonNull::new(
            unsafe { self.raw.as_ref() }
                .InterpreterInfo
                .cast::<MIDL_SERVER_INFO>()
                .cast_mut(),
        )
        .ok_or_else(|| Error::from_hresult(E_POINTER))?)
    }

    pub fn id(&self) -> GUID {
        unsafe { self.raw.as_ref() }.InterfaceId.SyntaxGUID
    }
}

pub struct RpcBindingVector {
    raw: NonNull<RPC_BINDING_VECTOR>,
}

impl RpcBindingVector {
    pub fn try_inquire_server() -> Result<Self> {
        let mut raw = ptr::null_mut();
        let status = unsafe { RpcServerInqBindings(&mut raw) };

        status.ok()?;

        Ok(RpcBindingVector {
            raw: unsafe { NonNull::new_unchecked(raw) },
        })
    }

    pub unsafe fn as_slice(&self) -> &[RPC_BINDING_HANDLE] {
        let deref = self.raw.as_ref();

        // Windows doesn't include RPC_BINDING_HANDLE. Explicit cast needed
        slice::from_raw_parts(
            deref.BindingH.as_ptr().cast::<RPC_BINDING_HANDLE>(),
            deref.Count as usize,
        )
    }
}

impl Drop for RpcBindingVector {
    fn drop(&mut self) {
        let _ = unsafe { RpcBindingVectorFree(&mut self.raw.as_ptr()) };
    }
}
