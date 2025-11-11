use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::ptr;

use anyhow::Context as _;
use windows::Win32::Foundation;
use windows::Win32::Security::Authentication::Identity;
use windows::Win32::Security::{Credentials, Cryptography};
use wrapper::ScopeGuard;

use crate::doctor::macros::diagnostic;
use crate::doctor::{Args, CertInspectProxy, Diagnostic, DiagnosticCtx, help};

struct ChainCtx {
    store: wrapper::CertStore,
    end_entity_info: wrapper::CertInfo,
}

pub(super) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
    let mut chain_ctx = None;

    diagnostic!(callback, schannel_open_in_memory_cert_store(&mut chain_ctx));

    let Some(mut chain_ctx) = chain_ctx else { return };

    if let Some(chain_path) = &args.chain_path {
        diagnostic!(callback, schannel_read_chain(&chain_path, &mut chain_ctx));
    } else if let Some(subject_name) = args.subject_name.as_deref()
        && args.allow_network
    {
        diagnostic!(
            callback,
            schannel_fetch_chain(&mut chain_ctx, subject_name, args.server_port)
        );
    }

    if let Some(subject_name) = args.subject_name.as_deref() {
        diagnostic!(callback, schannel_check_end_entity_cert(&chain_ctx, subject_name));
    }

    diagnostic!(callback, schannel_check_chain(&chain_ctx));
}

fn schannel_open_in_memory_cert_store(_: &mut DiagnosticCtx, chain_ctx: &mut Option<ChainCtx>) -> anyhow::Result<()> {
    let opened = wrapper::CertStore::open_in_memory().context("failed to open in-memory certificate store")?;

    *chain_ctx = Some(ChainCtx {
        store: opened,
        end_entity_info: wrapper::CertInfo::default(),
    });

    Ok(())
}

fn schannel_fetch_chain(
    ctx: &mut DiagnosticCtx,
    chain_ctx: &mut ChainCtx,
    subject_name: &str,
    port: Option<u16>,
) -> anyhow::Result<()> {
    info!("Connect to {subject_name}");

    let mut socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
        .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))
        .context("failed to connect to server...")?;

    // Acquire credentials handle.
    let mut credential = Credentials::SecHandle::default();

    {
        let mut authdata = Identity::SCHANNEL_CRED {
            dwVersion: Identity::SCHANNEL_CRED_VERSION,
            ..Default::default()
        };

        let package_name = windows::core::w!("Microsoft Unified Security Protocol Provider");

        debug!(
            schannel_cred_version = authdata.dwVersion,
            "Call AcquireCredentialsHandleW"
        );

        // SAFETY:
        // - package_name is a null-terminated UTF-16 string.
        // - Outgoing token (SECPKG_CRED_OUTBOUND).
        // - authdata is properly initialized above.
        unsafe {
            Identity::AcquireCredentialsHandleW(
                None,
                package_name,
                Identity::SECPKG_CRED_OUTBOUND,
                None,
                Some(&mut authdata as *mut _ as *mut core::ffi::c_void),
                None,
                None,
                &mut credential,
                None,
            )
            .context("AcquireCredentialsHandle failed")?;
        }

        debug!("Credentials acquired with success");
    }

    let credential = ScopeGuard::new(credential, |credential| {
        // The FreeCredentialsHandle function notifies the security system that the
        // credentials are no longer needed. An application calls this function to free the
        // credential handle acquired in the call to the AcquireCredentialsHandle (General)
        // function after calling the DeleteSecurityContext function to free any context
        // handles associated with the credential. When all references to this credential
        // set have been removed, the credentials themselves can be removed.

        // SAFETY: The handle is valid.
        if let Err(error) = unsafe { Identity::FreeCredentialsHandle(&credential) } {
            warn!(%error, "FreeCredentialsHandle failed");
        }
    });

    info!("Fetch server certificates");

    // Perform TLS handshake.
    // 1) Call `InitializeSecurityContext` to create/update the schannel context.
    // 2) If it returns `SEC_E_OK`, the TLS handshake is completed.
    // 3) If it returns `SEC_I_INCOMPLETE_CREDENTIALS`, the server requests a client certificate.
    // 4) If it returns `SEC_I_CONTINUE_NEEDED`, send the token to the server and read data.
    // 5) If it returns `SEC_E_INCOMPLETE_MESSAGE`, read more data from the server.
    // 6) Otherwise, read data from the server and go back to step 1.

    // Make sure server_name is a null-terminated UTF-16 string.
    let server_name: Vec<u16> = subject_name.encode_utf16().chain(Some(0)).collect();

    // For the security context.
    let mut ctx_handle = ScopeGuard::new(Credentials::SecHandle::default(), |ctx_handle| {
        // Check if the handle is valid.
        if ctx_handle == Credentials::SecHandle::default() {
            return;
        }

        // SAFETY:
        // - It is safe to call this even if the handle is not valid, but an error will be returned.
        // - Just in case, we check for the validity above.
        if let Err(error) = unsafe { Identity::DeleteSecurityContext(&ctx_handle) } {
            warn!(%error, "DeleteSecurityContext failed");
        }
    });

    let init_request_flags = Identity::ISC_REQ_CONFIDENTIALITY
        | Identity::ISC_REQ_INTEGRITY
        | Identity::ISC_REQ_REPLAY_DETECT
        | Identity::ISC_REQ_SEQUENCE_DETECT
        | Identity::ISC_REQ_MANUAL_CRED_VALIDATION
        | Identity::ISC_REQ_ALLOCATE_MEMORY
        | Identity::ISC_REQ_STREAM
        | Identity::ISC_REQ_USE_SUPPLIED_CREDS;

    debug!("InitializeSecurityContext Request Flags: {:#X?}", init_request_flags.0);

    let mut recv_buffer = Vec::new();

    loop {
        let mut inbufs = [
            wrapper::secbuf(Identity::SECBUFFER_TOKEN, Some(&mut recv_buffer)),
            wrapper::secbuf(Identity::SECBUFFER_EMPTY, None),
        ];
        let inbuf_desc = wrapper::secbuf_desc(&mut inbufs);

        let mut outbufs = ScopeGuard::new(
            [
                wrapper::secbuf(Identity::SECBUFFER_TOKEN, None),
                wrapper::secbuf(Identity::SECBUFFER_ALERT, None),
                wrapper::secbuf(Identity::SECBUFFER_EMPTY, None),
            ],
            |outbufs| {
                for buf in &outbufs {
                    if !buf.pvBuffer.is_null() {
                        // SAFETY: We assume the pointers returned by InitializeSecurityContextW are valid.
                        if let Err(error) = unsafe { Identity::FreeContextBuffer(buf.pvBuffer) } {
                            warn!(%error, "Failed to free context buffer");
                        }
                    }
                }
            },
        );
        let mut outbuf_desc = wrapper::secbuf_desc(outbufs.as_mut());

        let (phnewcontext, phcontext) = if *ctx_handle.as_ref() == Credentials::SecHandle::default() {
            (Some(ctx_handle.as_mut_ptr()), None)
        } else {
            (None, Some(ctx_handle.as_ptr()))
        };

        let mut attributes = 0;

        // SAFETY: FFI call with no outstanding preconditions.
        let ret = unsafe {
            Identity::InitializeSecurityContextW(
                Some(credential.as_ptr()),
                phcontext,
                Some(server_name.as_ptr()),
                init_request_flags,
                0,
                Identity::SECURITY_NATIVE_DREP,
                Some(&inbuf_desc),
                0,
                phnewcontext,
                Some(&mut outbuf_desc),
                &mut attributes,
                None,
            )
        };

        trace!("Context Attributes: {attributes:X}");

        match ret {
            // The security context was successfully initialized. There is no need for another
            // InitializeSecurityContext (General) call. If the function returns an output
            // token, that is, if the SECBUFFER_TOKEN in pOutput is of nonzero length, that
            // token must be sent to the server.
            Foundation::SEC_E_OK => {
                trace!("Got SEC_E_OK");

                recv_buffer.clear();

                let output_token = &outbufs.as_ref()[0];

                // SAFETY: The buffer is initialized by InitializeSecurityContextW when SEC_E_OK is returned.
                if let Err(error) = unsafe { send_output_token(&mut socket, output_token) } {
                    error!(%error, "Failed to send output token to server");
                }

                info!("TLS handshake ended with success");

                break;
            }

            // The client must send the output token to the server and wait for a return token.
            // The returned token is then passed in another call to InitializeSecurityContext
            // (General). The output token can be empty.
            Foundation::SEC_I_CONTINUE_NEEDED => {
                trace!("Got SEC_I_CONTINUE_NEEDED");

                recv_buffer.clear();

                let output_token = &outbufs.as_ref()[0];

                // SAFETY: The buffer is initialized by InitializeSecurityContextW when SEC_I_CONTINUE_NEEDED is returned.
                if let Err(error) = unsafe { send_output_token(&mut socket, output_token) } {
                    error!(%error, "Failed to send output token to server");
                    break;
                }
            }

            // Data for the whole message was not read from the wire. When this value is
            // returned, the pInput buffer contains a SecBuffer structure with a BufferType
            // member of SECBUFFER_MISSING. The cbBuffer member of SecBuffer contains a value
            // that indicates the number of additional bytes that the function must read
            // from the client before this function succeeds. While this number is not always
            // accurate, using it can help improve performance by avoiding multiple calls to
            // InitializeSecurityContext.
            Foundation::SEC_E_INCOMPLETE_MESSAGE => {
                trace!("Got SEC_E_INCOMPLETE_MESSAGE; read token from server");

                let additional_required = if inbufs[1].BufferType == Identity::SECBUFFER_MISSING {
                    inbufs[1].cbBuffer as usize
                } else {
                    1
                };

                trace!("At least {additional_required} additional bytes are required from the server");

                let len_before = recv_buffer.len();
                recv_buffer.resize(len_before + additional_required, 0);

                // Receive data from server.
                match socket.read_exact(&mut recv_buffer[len_before..]) {
                    Ok(()) => {
                        trace!("Received {additional_required} bytes from server");
                    }
                    Err(error) => {
                        error!(%error, "Failed to receive bytes from server");
                        break;
                    }
                }
            }

            // The server has requested client authentication, and the supplied credentials
            // either do not include a certificate or the certificate was not issued by a
            // certification authority that is trusted by the server.
            Foundation::SEC_I_INCOMPLETE_CREDENTIALS => {
                warn!("Server asked for client certificate");
                break;
            }

            // Otherwise, we are dealing with an error, and we should stop the procedure.
            _ => {
                let error = windows::core::Error::from_hresult(ret);
                warn!(%error, "Failed to complete TLS handshake");
                break;
            }
        }
    }

    let remote_end_entity_cert =
        wrapper::CertContext::schannel_remote_cert(ctx_handle.as_ref()).context("failed to retrieve remote cert")?;

    // Update the end entity info of the chain context.
    chain_ctx.end_entity_info = remote_end_entity_cert.to_info();

    let remote_chain = remote_end_entity_cert
        .chain()
        .context("failed to retrieve the remote chain")?;

    let mut certificates = Vec::new();

    remote_chain.for_each(|cert_idx, element| {
        if let Err(error) = chain_ctx.store.add_x509_encoded_certificate(element.cert.as_x509_der()) {
            warn!(cert_idx, %error, "Failed to add certificate to the store");
        }

        certificates.push(CertInspectProxy {
            friendly_name: element.cert.subject_friendly_name().ok(),
            der: element.cert.as_x509_der().to_owned(),
        });
    });

    crate::doctor::log_chain(certificates.iter());
    help::x509_io_link(ctx, certificates.iter());

    return Ok(());

    /// # Safety
    ///
    /// - The buffer must be initialized by the InitializeSecurityContextW function.
    /// - Make sure the buffer is not being mutated (e.g.: in a separate thread).
    unsafe fn send_output_token(socket: &mut TcpStream, token: &Identity::SecBuffer) -> std::io::Result<()> {
        let n_to_send = usize::try_from(token.cbBuffer).expect("u32-to-usize");

        if n_to_send > 0 && !token.pvBuffer.is_null() {
            trace!("Send {n_to_send}-byte output token");

            // SAFETY: InitializeSecurityContextW is initializing the structure properly.
            // - cbBuffer is the number of elements the pointer can read at the pointed memory location.
            // - The alignment is always valid (u8).
            // - The buffer is not being mutated at the same time.
            let to_send = unsafe { std::slice::from_raw_parts(token.pvBuffer as *const u8, n_to_send) };

            socket.write_all(to_send)
        } else {
            Ok(())
        }
    }
}

fn schannel_read_chain(ctx: &mut DiagnosticCtx, chain_path: &Path, chain_ctx: &mut ChainCtx) -> anyhow::Result<()> {
    info!("Read file at {}", chain_path.display());

    let mut file = std::fs::File::open(chain_path)
        .map(std::io::BufReader::new)
        .context("read file from disk")?;

    let mut certificates = Vec::new();

    for (idx, cert_der) in rustls_pemfile::certs(&mut file).enumerate() {
        let cert_der = cert_der.with_context(|| format!("failed to read certificate number {idx}"))?;

        let cert_ctx = chain_ctx
            .store
            .add_x509_encoded_certificate(&cert_der)
            .with_context(|| format!("failed to add certificate number {idx} to the store"))?;

        certificates.push(CertInspectProxy {
            friendly_name: cert_ctx.subject_friendly_name().ok(),
            der: cert_ctx.as_x509_der().to_owned(),
        });
    }

    crate::doctor::log_chain(certificates.iter());
    help::x509_io_link(ctx, certificates.iter());

    Ok(())
}

fn schannel_check_end_entity_cert(
    ctx: &mut DiagnosticCtx,
    chain_ctx: &ChainCtx,
    subject_name_to_verify: &str,
) -> anyhow::Result<()> {
    let end_entity_cert = chain_ctx
        .store
        .fetch_certificate(&chain_ctx.end_entity_info)
        .context("failed to fetch end entity cert from in-memory store")?;

    info!("Inspect the end entity certificate");

    let mut certificate_names = Vec::new();

    for name in end_entity_cert
        .subject_dns_names()
        .context("failed to fetch DNS names")?
    {
        info!("Found name: {name}");
        certificate_names.push(name);
    }

    info!("Verify validity for subject name {subject_name_to_verify}");

    let success = certificate_names
        .into_iter()
        .any(|certificate_name| crate::doctor::wildcard_host_match(&certificate_name, subject_name_to_verify));

    if !success {
        help::cert_invalid_hostname(ctx, subject_name_to_verify);
        anyhow::bail!(
            "the subject name '{subject_name_to_verify}' does not match any domain identified by the certificate"
        );
    }

    Ok(())
}

fn schannel_check_chain(ctx: &mut DiagnosticCtx, chain_ctx: &ChainCtx) -> anyhow::Result<()> {
    let end_entity_cert = chain_ctx
        .store
        .fetch_certificate(&chain_ctx.end_entity_info)
        .context("failed to fetch end entity cert from in-memory store")?;

    let chain = end_entity_cert.chain().context("failed to get certificate chain")?;

    // Inspect each certificate of the chain and look for suspicious trust status flags.
    chain.for_each(|cert_idx, element| {
        let cert_name = if let Ok(name) = element.cert.subject_friendly_name() {
            name
        } else {
            String::from("?")
        };

        let trust_status = element.trust_status;

        info!(
            cert_idx,
            cert_name,
            "Certificate error status = {:#010X}, info status = {:#010X}",
            trust_status.dwErrorStatus,
            trust_status.dwInfoStatus
        );

        if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_NOT_TIME_VALID) {
            error!(cert_idx, cert_name, "CERT_TRUST_IS_NOT_TIME_VALID");
        }

        if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_REVOKED) {
            error!(cert_idx, cert_name, "CERT_TRUST_IS_REVOKED");
        }

        if flags_contains(
            trust_status.dwErrorStatus,
            Cryptography::CERT_TRUST_IS_NOT_SIGNATURE_VALID,
        ) {
            error!(cert_idx, cert_name, "CERT_TRUST_IS_NOT_SIGNATURE_VALID");
        }

        if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_UNTRUSTED_ROOT) {
            error!(cert_idx, cert_name, "CERT_TRUST_IS_UNTRUSTED_ROOT");
        }
    });

    let trust_status = chain.trust_status();

    info!(
        "Chain error status = {:#010X}, info status = {:#010X}",
        trust_status.dwErrorStatus, trust_status.dwInfoStatus
    );

    if flags_contains(trust_status.dwInfoStatus, Cryptography::CERT_TRUST_IS_COMPLEX_CHAIN) {
        info!("CERT_TRUST_IS_COMPLEX_CHAIN");
    }

    if trust_status.dwErrorStatus == 0 {
        info!("Certificate chain is valid");
        return Ok(());
    }

    if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_NOT_TIME_VALID) {
        error!("CERT_TRUST_IS_NOT_TIME_VALID");
        help::cert_is_expired(ctx);
    }

    if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_REVOKED) {
        error!("CERT_TRUST_IS_REVOKED");
    }

    if flags_contains(
        trust_status.dwErrorStatus,
        Cryptography::CERT_TRUST_IS_NOT_SIGNATURE_VALID,
    ) {
        error!("CERT_TRUST_IS_NOT_SIGNATURE_VALID");
    }

    if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_UNTRUSTED_ROOT) {
        error!("CERT_TRUST_IS_UNTRUSTED_ROOT");
        help::cert_unknown_issuer(ctx);
    }

    if flags_contains(trust_status.dwErrorStatus, Cryptography::CERT_TRUST_IS_PARTIAL_CHAIN) {
        error!("CERT_TRUST_IS_PARTIAL_CHAIN");
    }

    if flags_contains(
        trust_status.dwErrorStatus,
        Cryptography::CERT_TRUST_CTL_IS_NOT_TIME_VALID,
    ) {
        error!("CERT_TRUST_CTL_IS_NOT_TIME_VALID");
    }

    if flags_contains(
        trust_status.dwErrorStatus,
        Cryptography::CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID,
    ) {
        error!("CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID");
    }

    anyhow::bail!(
        "certificate chain is not trusted: error status = {:#010X}, info status = {:#010X}",
        trust_status.dwErrorStatus,
        trust_status.dwInfoStatus
    );

    fn flags_contains(flags: u32, mask: u32) -> bool {
        flags & mask == mask
    }
}

mod wrapper {
    use super::*;

    pub(super) struct ScopeGuard<T, F: FnOnce(T)>(Option<ScopeGuardInner<T, F>>);

    struct ScopeGuardInner<T, F: FnOnce(T)> {
        value: T,
        on_drop_fn: F,
    }

    impl<T, F: FnOnce(T)> ScopeGuard<T, F> {
        pub(super) fn new(value: T, on_drop_fn: F) -> Self {
            Self(Some(ScopeGuardInner { value, on_drop_fn }))
        }

        pub(super) fn as_ref(&self) -> &T {
            &self.0.as_ref().expect("always Some").value
        }

        pub(super) fn as_mut(&mut self) -> &mut T {
            &mut self.0.as_mut().expect("always Some").value
        }

        pub(super) fn as_ptr(&self) -> *const T {
            &self.0.as_ref().expect("always Some").value as *const _
        }

        pub(super) fn as_mut_ptr(&mut self) -> *mut T {
            &mut self.0.as_mut().expect("always Some").value as *mut _
        }
    }

    impl<T, F: FnOnce(T)> Drop for ScopeGuard<T, F> {
        fn drop(&mut self) {
            let inner = self.0.take().expect("always Some");
            (inner.on_drop_fn)(inner.value)
        }
    }

    pub(super) struct CertStore {
        /// INVARIANT: A valid pointer to a properly initialized certificate store.
        ptr: Cryptography::HCERTSTORE,
    }

    impl CertStore {
        // Open an in-memory certificate store.
        pub(super) fn open_in_memory() -> windows::core::Result<Self> {
            // SAFETY: FFI call with no outstanding preconditions.
            let cert_store = unsafe {
                Cryptography::CertOpenStore(
                    Cryptography::CERT_STORE_PROV_MEMORY,
                    Cryptography::CERT_QUERY_ENCODING_TYPE(0),
                    None,
                    Cryptography::CERT_OPEN_STORE_FLAGS(0),
                    None,
                )?
            };

            Ok(Self { ptr: cert_store })
        }

        pub(super) fn add_x509_encoded_certificate(&mut self, cert: &[u8]) -> windows::core::Result<CertContext<'_>> {
            let mut cert_ctx: *mut Cryptography::CERT_CONTEXT = ptr::null_mut();

            // SAFETY: FFI call with no outstanding preconditions.
            unsafe {
                Cryptography::CertAddEncodedCertificateToStore(
                    Some(self.ptr),
                    Cryptography::X509_ASN_ENCODING,
                    cert,
                    Cryptography::CERT_STORE_ADD_ALWAYS,
                    Some(&mut cert_ctx),
                )?;
            }

            Ok(CertContext {
                ptr: cert_ctx,
                _marker: core::marker::PhantomData,
            })
        }

        pub(super) fn fetch_certificate(&self, info: &CertInfo) -> windows::core::Result<CertContext<'_>> {
            let serial_number_blob = Cryptography::CRYPT_INTEGER_BLOB {
                cbData: u32::try_from(info.serial.len()).expect("usize-to-u32"),
                pbData: info.serial.as_ptr().cast_mut(),
            };

            let issuer_blob = Cryptography::CRYPT_INTEGER_BLOB {
                cbData: u32::try_from(info.issuer.len()).expect("usize-to-u32"),
                pbData: info.issuer.as_ptr().cast_mut(),
            };

            let info = Cryptography::CERT_INFO {
                SerialNumber: serial_number_blob,
                Issuer: issuer_blob,
                ..Default::default()
            };

            // SAFETY:
            // - The pointers held in the CERT_INFO struct are not freed before the end of this function (shared reference passed in parameters).
            // - The pointer mutability is not a problem, because CertGetSubjectCertificateFromStore is not mutating the values.
            let ptr = unsafe {
                Cryptography::CertGetSubjectCertificateFromStore(self.ptr, Cryptography::X509_ASN_ENCODING, &info)
            };

            if ptr.is_null() {
                Err(windows::core::Error::from_win32())
            } else {
                Ok(CertContext {
                    ptr,
                    _marker: core::marker::PhantomData,
                })
            }
        }
    }

    impl Drop for CertStore {
        fn drop(&mut self) {
            // SAFETY: The store handle is owned by us.
            let res = unsafe { Cryptography::CertCloseStore(Some(self.ptr), 0) };

            if let Err(error) = res {
                warn!(%error, "failed to close certificate store");
            }
        }
    }

    #[repr(transparent)]
    pub(super) struct CertContextRef<'store> {
        /// INVARIANT: A valid pointer to a properly initialized CERT_CONTEXT.
        ptr: *const Cryptography::CERT_CONTEXT,
        _marker: core::marker::PhantomData<&'store CertStore>,
    }

    impl CertContextRef<'_> {
        pub(super) fn as_x509_der(&self) -> &[u8] {
            // SAFETY: Pointer is valid per invariant.
            let cert_context = unsafe { self.ptr.read() };

            assert_eq!(cert_context.dwCertEncodingType, Cryptography::X509_ASN_ENCODING);

            let length = usize::try_from(cert_context.cbCertEncoded).expect("u32-to-usize");

            // SAFETY: The length is correctly retrieved from the same context.
            unsafe { std::slice::from_raw_parts(cert_context.pbCertEncoded, length) }
        }

        pub(super) fn to_info(&self) -> CertInfo {
            // SAFETY: Pointer is valid per invariant.
            let cert_context = unsafe { self.ptr.read() };

            // SAFETY: CERT_CONTEXT is properly initialized per invariant.
            let cert_info = unsafe { cert_context.pCertInfo.read() };

            // Note that simply copying and returning the CERT_INFO struct is
            // dangerous as most of the data will be left dangling after the
            // CERT_CONTEXT is freed. Instead, we perform a deep copy of the
            // relevant fields into a separate opaque type.

            // SAFETY: CERT_CONTEXT is properly initialized per invariant.
            let serial = unsafe {
                std::slice::from_raw_parts(cert_info.SerialNumber.pbData, cert_info.SerialNumber.cbData as usize)
            };

            // SAFETY: CERT_CONTEXT is properly initialized per invariant.
            let issuer =
                unsafe { std::slice::from_raw_parts(cert_info.Issuer.pbData, cert_info.Issuer.cbData as usize) };

            CertInfo {
                issuer: issuer.to_vec(),
                serial: serial.to_vec(),
            }
        }

        fn subject_name<const BUF_SIZE: usize>(
            &self,
            name_type: u32,
            flags: u32,
        ) -> Result<String, std::string::FromUtf16Error> {
            let mut dst = [0u16; BUF_SIZE];

            // SAFETY: FFI call with no outstanding preconditions.
            let ret = unsafe { Cryptography::CertGetNameStringW(self.ptr, name_type, flags, None, Some(&mut dst)) };

            let string_length = usize::try_from(ret).expect("u32-to-usize") - 1;

            String::from_utf16(&dst[..string_length])
        }

        pub(super) fn subject_friendly_name(&self) -> Result<String, std::string::FromUtf16Error> {
            self.subject_name::<256>(Cryptography::CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0)
        }

        pub(super) fn subject_dns_names(&self) -> Result<impl Iterator<Item = String>, std::string::FromUtf16Error> {
            let dns_names = self.subject_name::<1024>(
                Cryptography::CERT_NAME_DNS_TYPE,
                Cryptography::CERT_NAME_SEARCH_ALL_NAMES_FLAG,
            )?;

            return Ok(Iter {
                inner: dns_names,
                idx: 0,
            });

            struct Iter {
                inner: String,
                idx: usize,
            }

            impl Iterator for Iter {
                type Item = String;

                fn next(&mut self) -> Option<Self::Item> {
                    while self.idx < self.inner.len() {
                        let len = self.inner[self.idx..].find('\0')?;
                        let s = &self.inner[self.idx..self.idx + len];
                        self.idx += len + 1;

                        if !s.is_empty() {
                            return Some(s.to_lowercase());
                        }
                    }

                    None
                }
            }
        }

        pub(super) fn chain(&self) -> windows::core::Result<ChainContext<'_>> {
            let mut chain_context: *mut Cryptography::CERT_CHAIN_CONTEXT = ptr::null_mut();

            let chain_para = Cryptography::CERT_CHAIN_PARA {
                cbSize: u32::try_from(size_of::<Cryptography::CERT_CHAIN_PARA>()).expect("always small enough"),
                ..Default::default()
            };

            // SAFETY:
            // - The pointer is valid.
            // - The store is not yet closed. This is enforced by the Rust compiler using the 'store lifetime.
            let store = unsafe { (*self.ptr).hCertStore };

            // SAFETY: FFI call with no outstanding preconditions.
            unsafe {
                Cryptography::CertGetCertificateChain(
                    None,
                    self.ptr,
                    None,
                    Some(store),
                    &chain_para,
                    0,
                    None,
                    &mut chain_context,
                )?;
            }

            // The returned pointer is freed when passed as the
            // pPrevCertContext parameter on a subsequent call. Otherwise, the
            // pointer must be freed by calling CertFreeCertificateContext. A
            // non-NULL pPrevCertContext passed to CertEnumCertificatesInStore
            // is always freed even for an error.

            Ok(ChainContext {
                ptr: chain_context,
                _marker: core::marker::PhantomData,
            })
        }
    }

    #[repr(transparent)]
    pub(super) struct CertContext<'store> {
        /// INVARIANT: A valid pointer to a properly initialized CERT_CONTEXT.
        ptr: *mut Cryptography::CERT_CONTEXT,
        _marker: core::marker::PhantomData<&'store CertStore>,
    }

    impl<'store> CertContext<'store> {
        pub(super) fn schannel_remote_cert(ctx_handle: &'store Credentials::SecHandle) -> windows::core::Result<Self> {
            let mut cert_ctx: *mut Cryptography::CERT_CONTEXT = ptr::null_mut();

            // It’s important to use SECPKG_ATTR_REMOTE_CERT_CHAIN instead of SECPKG_ATTR_REMOTE_CERT_CHAIN_CONTEXT.
            // Indeed, SECPKG_ATTR_REMOTE_CERT_CHAIN can be retrieved before the handshake completes,
            // while SECPKG_ATTR_REMOTE_CERT_CHAIN_CONTEXT will lead to SEC_E_INVALID_HANDLE being returned.
            let attribute = Identity::SECPKG_ATTR(Identity::SECPKG_ATTR_REMOTE_CERT_CHAIN);

            // SAFETY: When called with SECPKG_ATTR_REMOTE_CERT_CHAIN, the returned buffer is set to a PCCERT_CONTEXT.
            unsafe {
                Identity::QueryContextAttributesW(
                    ctx_handle as *const Credentials::SecHandle,
                    attribute,
                    &mut cert_ctx as *mut _ as *mut core::ffi::c_void,
                )?;
            }

            Ok(Self {
                ptr: cert_ctx,
                _marker: std::marker::PhantomData,
            })
        }
    }

    impl Drop for CertContext<'_> {
        fn drop(&mut self) {
            // SAFETY: The CERT_CONTEXT handle is owned by us.
            let ret = unsafe { Cryptography::CertFreeCertificateContext(Some(self.ptr)) };

            if !ret.as_bool() {
                let error = windows::core::Error::from_win32();
                warn!(%error, "failed to free certificate context");
            }
        }
    }

    impl<'store> std::ops::Deref for CertContext<'store> {
        type Target = CertContextRef<'store>;

        fn deref(&self) -> &Self::Target {
            debug_assert!(!self.ptr.is_null());

            // SAFETY:
            // - Both CertContext and CertContextRef are #[repr(transparent)] over a raw pointer on a CERT_CONTEXT.
            // - Per invariants, the pointers are on valid CERT_CONTEXT.
            unsafe { &*(self as *const _ as *const CertContextRef<'_>) }
        }
    }

    pub(super) struct ChainContext<'store> {
        /// INVARIANT: A valid pointer to a properly initialized CERT_CHAIN_CONTEXT.
        ptr: *const Cryptography::CERT_CHAIN_CONTEXT,
        _marker: core::marker::PhantomData<&'store CertStore>,
    }

    impl<'store> ChainContext<'store> {
        pub(super) fn trust_status(&self) -> Cryptography::CERT_TRUST_STATUS {
            // SAFETY: Pointer is valid per invariants.
            let chain_context = unsafe { self.ptr.read() };
            chain_context.TrustStatus
        }

        #[expect(clippy::similar_names)] // pp and p are close, but this is fine.
        pub(super) fn for_each(&self, mut f: impl for<'cert> FnMut(usize, &ChainElement<'store, 'cert>)) {
            // SAFETY: Pointer is valid per invariants.
            let chain_context: &Cryptography::CERT_CHAIN_CONTEXT = unsafe { &*self.ptr };

            let mut element_idx = 0;

            for simple_chain_offset in 0..chain_context.cChain {
                let simple_chain_offset = usize::try_from(simple_chain_offset).expect("u32-to-usize");

                // SAFETY: CERT_CHAIN_CONTEXT is properly initialized per invariant.
                let pp_simple_chain = unsafe { chain_context.rgpChain.add(simple_chain_offset) };

                // SAFETY: CERT_CHAIN_CONTEXT is properly initialized per invariant.
                let p_simple_chain = unsafe { pp_simple_chain.read() };

                if p_simple_chain.is_null() {
                    debug!("p_simple_chain is null");
                    continue;
                }

                // SAFETY: CERT_CHAIN_CONTEXT is properly initialized per invariant.
                let simple_chain = unsafe { p_simple_chain.read() };

                for element_offset in 0..simple_chain.cElement {
                    let element_offset = usize::try_from(element_offset).expect("u32-to-usize");

                    // SAFETY: CERT_CHAIN_CONTEXT is properly initialized per invariant.
                    let pp_chain_element = unsafe { simple_chain.rgpElement.add(element_offset) };

                    // SAFETY: CERT_CHAIN_CONTEXT is properly initialized per invariant.
                    let p_chain_element = unsafe { pp_chain_element.read() };

                    if p_chain_element.is_null() {
                        debug!("p_chain_element is null");
                        continue;
                    }

                    element_idx += 1;

                    // SAFETY: CERT_CHAIN_CONTEXT is properly initialized per invariant.
                    let chain_element = unsafe { p_chain_element.read() };

                    // Access the certificate context
                    let p_cert_context = chain_element.pCertContext;

                    if p_cert_context.is_null() {
                        debug!("p_cert_context is null");
                        continue;
                    }

                    let cert_context = CertContextRef {
                        ptr: p_cert_context,
                        _marker: std::marker::PhantomData,
                    };

                    let chain_element = ChainElement {
                        cert: &cert_context,
                        trust_status: chain_element.TrustStatus,
                    };

                    (f)(element_idx - 1, &chain_element);
                }
            }
        }
    }

    impl Drop for ChainContext<'_> {
        fn drop(&mut self) {
            // SAFETY: The CERT_CHAIN_CONTEXT handle is owned by us.
            unsafe { Cryptography::CertFreeCertificateChain(self.ptr) };
        }
    }

    pub(super) struct ChainElement<'store, 'cert> {
        pub cert: &'cert CertContextRef<'store>,
        pub trust_status: Cryptography::CERT_TRUST_STATUS,
    }

    #[derive(Default)]
    pub(super) struct CertInfo {
        issuer: Vec<u8>,
        serial: Vec<u8>,
    }

    pub(super) fn secbuf(buftype: u32, bytes: Option<&mut [u8]>) -> Identity::SecBuffer {
        let (ptr, len) = match bytes {
            Some(bytes) => (bytes.as_mut_ptr(), u32::try_from(bytes.len()).expect("usize-to-u32")),
            None => (ptr::null_mut(), 0),
        };

        Identity::SecBuffer {
            BufferType: buftype,
            cbBuffer: len,
            pvBuffer: ptr as *mut core::ffi::c_void,
        }
    }

    pub(super) fn secbuf_desc(bufs: &mut [Identity::SecBuffer]) -> Identity::SecBufferDesc {
        Identity::SecBufferDesc {
            ulVersion: Identity::SECBUFFER_VERSION,
            cBuffers: u32::try_from(bufs.len()).expect("usize-to-u32"),
            pBuffers: bufs.as_mut_ptr(),
        }
    }
}
