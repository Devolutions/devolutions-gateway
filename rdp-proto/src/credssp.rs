pub mod ts_request;

use self::ts_request::{TsRequest, NONCE_SIZE};
use crate::{
    encryption::compute_sha256,
    nego::NegotiationRequestFlags,
    ntlm::{Ntlm, NTLM_VERSION_SIZE},
    sspi::{self, AuthIdentity, PackageType, Sspi, SspiError, SspiErrorType, SspiOk},
    Credentials,
};

const HASH_MAGIC_LEN: usize = 38;
const SERVER_CLIENT_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Server-To-Client Binding Hash\0";
const CLIENT_SERVER_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Client-To-Server Binding Hash\0";

pub struct CredSspClient {
    state: CredSspState,
    ts_request: TsRequest,
    context: Option<CredSspContext>,
    credentials: Credentials,
    version: Vec<u8>,
    public_key: Vec<u8>,
    nego_flags: NegotiationRequestFlags,
}

pub struct CredSspServer {
    state: CredSspState,
    ts_request: TsRequest,
    context: Option<CredSspContext>,
    credentials: Credentials,
    version: Vec<u8>,
    public_key: Vec<u8>,
}

pub enum CredSspResult {
    ReplyNeeded(TsRequest),
    FinalMessage(TsRequest),
    Finished,
}

pub trait CredSsp {
    fn update_ts_request(&mut self, ts_request: TsRequest) -> sspi::Result<()>;
    fn process(&mut self) -> sspi::Result<CredSspResult>;
}

#[derive(Copy, Clone, PartialEq)]
enum CredSspState {
    Initial,
    NegoToken,
    AuthInfo,
    Final,
}

#[derive(PartialEq)]
enum EndpointType {
    Client,
    Server,
}

struct CredSspContext {
    sspi_context: SspiProvider,
    send_seq_num: u32,
    recv_seq_num: u32,
}

enum SspiProvider {
    NtlmContext(Ntlm),
}

impl CredSspClient {
    pub fn new(
        public_key: Vec<u8>,
        credentials: Credentials,
        version: Vec<u8>,
        nego_flags: NegotiationRequestFlags,
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::Initial,
            ts_request: TsRequest::with_random_nonce()?,
            context: None,
            credentials,
            version,
            public_key,
            nego_flags,
        })
    }
}

impl CredSspServer {
    pub fn new(public_key: Vec<u8>, credentials: Credentials, version: Vec<u8>) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::Initial,
            ts_request: TsRequest::with_random_nonce()?,
            context: None,
            credentials,
            version,
            public_key,
        })
    }
}

impl SspiProvider {
    pub fn new_ntlm(credentials: Credentials, version: Vec<u8>) -> Self {
        let mut ntlm_version = [0x00; NTLM_VERSION_SIZE];
        ntlm_version.clone_from_slice(version.as_ref());

        SspiProvider::NtlmContext(Ntlm::new(credentials, ntlm_version))
    }
}

impl CredSsp for CredSspClient {
    fn update_ts_request(&mut self, ts_request: TsRequest) -> sspi::Result<()> {
        self.ts_request.update(ts_request)?;
        self.ts_request.check_error()
    }
    fn process(&mut self) -> sspi::Result<CredSspResult> {
        loop {
            match self.state {
                CredSspState::Initial => {
                    self.context = Some(CredSspContext::new(SspiProvider::new_ntlm(
                        self.credentials.clone(),
                        self.version.clone(),
                    )));

                    self.state = CredSspState::NegoToken;
                }
                CredSspState::NegoToken => {
                    let input = self.ts_request.nego_tokens.take().unwrap_or_default();
                    let mut output = Vec::new();
                    let status = self
                        .context
                        .as_mut()
                        .unwrap()
                        .sspi_context
                        .initialize_security_context(input.as_slice(), &mut output)?;
                    self.ts_request.nego_tokens = Some(output);
                    if status == SspiOk::CompleteNeeded {
                        self.ts_request.pub_key_auth = Some(self.context.as_mut().unwrap().encrypt_public_key(
                            self.public_key.as_ref(),
                            EndpointType::Client,
                            &self.ts_request.client_nonce,
                            self.ts_request.peer_version.expect(
                                "An encrypt public key client function cannot be fired without any incoming TSRequest",
                            ),
                        )?);
                        self.state = CredSspState::AuthInfo;
                    }

                    return Ok(CredSspResult::ReplyNeeded(self.ts_request.clone()));
                }
                CredSspState::AuthInfo => {
                    self.ts_request.nego_tokens = None;

                    let pub_key_auth = self.ts_request.pub_key_auth.take().ok_or_else(|| {
                        SspiError::new(
                            SspiErrorType::InvalidToken,
                            String::from("Expected an encrypted public key"),
                        )
                    })?;
                    self.context.as_mut().unwrap().decrypt_public_key(
                        self.public_key.as_ref(),
                        pub_key_auth.as_ref(),
                        EndpointType::Client,
                        &self.ts_request.client_nonce,
                        self.ts_request.peer_version.expect(
                            "An decrypt public key client function cannot be fired without any incoming TSRequest",
                        ),
                    )?;

                    self.ts_request.auth_info =
                        Some(self.context.as_mut().unwrap().encrypt_ts_credentials(self.nego_flags)?);

                    self.state = CredSspState::Final;

                    return Ok(CredSspResult::FinalMessage(self.ts_request.clone()));
                }
                CredSspState::Final => return Ok(CredSspResult::Finished),
            }
        }
    }
}

impl CredSsp for CredSspServer {
    fn update_ts_request(&mut self, ts_request: TsRequest) -> sspi::Result<()> {
        self.ts_request.update(ts_request)
    }
    fn process(&mut self) -> sspi::Result<CredSspResult> {
        loop {
            match self.state {
                CredSspState::Initial => {
                    self.context = Some(CredSspContext::new(SspiProvider::new_ntlm(
                        self.credentials.clone(),
                        self.version.clone(),
                    )));

                    self.state = CredSspState::NegoToken;
                }
                CredSspState::NegoToken => {
                    let input = self.ts_request.nego_tokens.take().ok_or_else(|| {
                        SspiError::new(SspiErrorType::InvalidToken, String::from("Got empty nego_tokens field"))
                    })?;
                    let mut output = Vec::new();
                    match self
                        .context
                        .as_mut()
                        .unwrap()
                        .sspi_context
                        .accept_security_context(input.as_slice(), &mut output)
                        {
                            Ok(SspiOk::ContinueNeeded) => {
                                self.ts_request.nego_tokens = Some(output);
                            }
                            Ok(SspiOk::CompleteNeeded) => {
                                self.context.as_mut().unwrap().sspi_context.complete_auth_token()?;
                                self.ts_request.nego_tokens = None;

                                let pub_key_auth = self.ts_request.pub_key_auth.take().ok_or_else(|| {
                                    SspiError::new(
                                        SspiErrorType::InvalidToken,
                                        String::from("Expected an encrypted public key"),
                                    )
                                })?;
                                self.context.as_mut().unwrap().decrypt_public_key(
                                    self.public_key.as_ref(),
                                    pub_key_auth.as_ref(),
                                    EndpointType::Server,
                                    &self.ts_request.client_nonce,
                                    self.ts_request.peer_version.expect(
                                        "An decrypt public key server function cannot be fired without any incoming TSRequest",
                                    ),
                                )?;
                                self.ts_request.pub_key_auth = Some(self.context.as_mut().unwrap().encrypt_public_key(
                                    self.public_key.as_ref(),
                                    EndpointType::Server,
                                    &self.ts_request.client_nonce,
                                    self.ts_request.peer_version.expect(
                                        "An encrypt public key server function cannot be fired without any incoming TSRequest",
                                    ),
                                )?);

                                self.state = CredSspState::AuthInfo;
                            }
                            Err(e) => {
                                self.ts_request.error_code =
                                    Some(((e.error_type as i64 & 0x0000_FFFF) | (0x7 << 16) | 0xC000_0000) as u32);
                                return Err(e);
                            }
                        };

                    return Ok(CredSspResult::ReplyNeeded(self.ts_request.clone()));
                }
                CredSspState::AuthInfo => {
                    let auth_info = self.ts_request.auth_info.take().ok_or_else(|| {
                        SspiError::new(
                            SspiErrorType::InvalidToken,
                            String::from("Expected an encrypted ts credentials"),
                        )
                    })?;
                    let read_identity = self.context.as_mut().unwrap().decrypt_ts_credentials(&auth_info)?;
                    self.state = CredSspState::Final;

                    if self
                        .context
                        .as_mut()
                        .unwrap()
                        .sspi_context
                        .identity()
                        .is_eq(&read_identity)
                    {
                        return Ok(CredSspResult::Finished);
                    } else {
                        return Err(SspiError::new(
                            SspiErrorType::MessageAltered,
                            String::from("Got invalid credentials from the client"),
                        ));
                    }
                }
                CredSspState::Final => return Ok(CredSspResult::Finished),
            }
        }
    }
}

impl CredSspContext {
    fn new(sspi_context: SspiProvider) -> Self {
        Self {
            send_seq_num: 0,
            recv_seq_num: 0,
            sspi_context,
        }
    }

    fn encrypt_public_key(
        &mut self,
        public_key: &[u8],
        endpoint: EndpointType,
        client_nonce: &Option<[u8; NONCE_SIZE]>,
        peer_version: u32,
    ) -> sspi::Result<Vec<u8>> {
        let hash_magic = match endpoint {
            EndpointType::Client => CLIENT_SERVER_HASH_MAGIC,
            EndpointType::Server => SERVER_CLIENT_HASH_MAGIC,
        };

        if peer_version < 5 {
            self.encrypt_public_key_echo(public_key, endpoint)
        } else {
            self.encrypt_public_key_hash(
                public_key,
                hash_magic,
                &client_nonce.ok_or(SspiError::new(
                    SspiErrorType::InvalidToken,
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
                ))?,
            )
        }
    }

    fn decrypt_public_key(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
        client_nonce: &Option<[u8; NONCE_SIZE]>,
        peer_version: u32,
    ) -> sspi::Result<()> {
        let hash_magic = match endpoint {
            EndpointType::Client => SERVER_CLIENT_HASH_MAGIC,
            EndpointType::Server => CLIENT_SERVER_HASH_MAGIC,
        };

        if peer_version < 5 {
            self.decrypt_public_key_echo(public_key, encrypted_public_key, endpoint)
        } else {
            self.decrypt_public_key_hash(
                public_key,
                encrypted_public_key,
                hash_magic,
                &client_nonce.ok_or(SspiError::new(
                    SspiErrorType::InvalidToken,
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
                ))?,
            )
        }
    }

    fn encrypt_public_key_echo(&mut self, public_key: &[u8], endpoint: EndpointType) -> sspi::Result<Vec<u8>> {
        let mut public_key = public_key.to_vec();

        match self.sspi_context.package_type() {
            PackageType::Ntlm => {
                if endpoint == EndpointType::Server {
                    integer_increment_le(&mut public_key);
                }
            }
        };

        self.encrypt_message(&public_key)
    }

    fn encrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> sspi::Result<Vec<u8>> {
        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let encrypted_public_key = compute_sha256(&data);

        self.encrypt_message(&encrypted_public_key)
    }

    fn decrypt_public_key_echo(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
    ) -> sspi::Result<()> {
        let mut decrypted_public_key = self.decrypt_message(encrypted_public_key)?;
        if endpoint == EndpointType::Client {
            integer_decrement_le(&mut decrypted_public_key);
        }

        if public_key != decrypted_public_key.as_slice() {
            return Err(SspiError::new(
                SspiErrorType::MessageAltered,
                String::from("Could not verify a public key echo"),
            ));
        }

        Ok(())
    }

    fn decrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> sspi::Result<()> {
        let decrypted_public_key = self.decrypt_message(encrypted_public_key)?;

        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let expected_public_key = compute_sha256(&data);

        if expected_public_key.as_ref() != decrypted_public_key.as_slice() {
            return Err(SspiError::new(
                SspiErrorType::MessageAltered,
                String::from("Could not verify a public key hash"),
            ));
        }

        Ok(())
    }

    fn encrypt_ts_credentials(&mut self, nego_flags: NegotiationRequestFlags) -> sspi::Result<Vec<u8>> {
        let ts_credentials = ts_request::write_ts_credentials(self.sspi_context.identity(), nego_flags)?;

        self.encrypt_message(&ts_credentials)
    }

    fn decrypt_ts_credentials(&mut self, auth_info: &[u8]) -> sspi::Result<AuthIdentity> {
        let ts_credentials_buffer = self.decrypt_message(&auth_info)?;

        Ok(ts_request::read_ts_credentials(ts_credentials_buffer.as_slice())?)
    }

    fn encrypt_message(&mut self, buffer: &[u8]) -> sspi::Result<Vec<u8>> {
        let send_seq_num = self.send_seq_num;
        let encrypted_buffer = self.sspi_context.encrypt_message(buffer, send_seq_num)?;
        self.send_seq_num += 1;

        // there will be magic transform for the kerberos

        Ok(encrypted_buffer)
    }

    fn decrypt_message(&mut self, buffer: &[u8]) -> sspi::Result<Vec<u8>> {
        let recv_seq_num = self.recv_seq_num;
        let decrypted_buffer = self.sspi_context.decrypt_message(buffer, recv_seq_num)?;
        self.recv_seq_num += 1;

        Ok(decrypted_buffer)
    }
}

impl Sspi for SspiProvider {
    fn package_type(&self) -> PackageType {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.package_type(),
        }
    }
    fn identity(&self) -> &AuthIdentity {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.identity(),
        }
    }
    fn initialize_security_context(
        &mut self,
        input: impl std::io::Read,
        output: impl std::io::Write,
    ) -> sspi::SspiResult {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.initialize_security_context(input, output),
        }
    }
    fn accept_security_context(&mut self, input: impl std::io::Read, output: impl std::io::Write) -> sspi::SspiResult {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.accept_security_context(input, output),
        }
    }
    fn complete_auth_token(&mut self) -> sspi::Result<()> {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.complete_auth_token(),
        }
    }
    fn encrypt_message(&mut self, input: &[u8], message_seq_number: u32) -> sspi::Result<Vec<u8>> {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.encrypt_message(input, message_seq_number),
        }
    }
    fn decrypt_message(&mut self, input: &[u8], message_seq_number: u32) -> sspi::Result<Vec<u8>> {
        match self {
            SspiProvider::NtlmContext(ntlm) => ntlm.decrypt_message(input, message_seq_number),
        }
    }
}

fn integer_decrement_le(buffer: &mut [u8]) {
    for elem in buffer.iter_mut() {
        let (value, overflow) = elem.overflowing_sub(1);
        *elem = value;
        if !overflow {
            break;
        }
    }
}

fn integer_increment_le(buffer: &mut [u8]) {
    for elem in buffer.iter_mut() {
        let (value, overflow) = elem.overflowing_add(1);
        *elem = value;
        if !overflow {
            break;
        }
    }
}
