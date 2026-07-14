use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use anyhow::Context as _;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty, Sig, client, server};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::credential::ArcCredentialEntry;

pub async fn run<C, S>(client_stream: C, target_stream: S, credential_entry: ArcCredentialEntry) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let credential_mapping = credential_entry.mapping.as_ref().context("no credential mapping")?;
    let (proxy_username, proxy_password) = credential_mapping.proxy.decrypt_password()?;
    let (target_username, target_password) = credential_mapping.target.decrypt_password()?;

    let target_config = Arc::new(client::Config::default());
    let mut target_session = client::connect_stream(target_config, target_stream, TargetClient).await?;
    let authentication = target_session
        .authenticate_password(target_username, target_password.expose_secret())
        .await?;
    anyhow::ensure!(authentication.success(), "target SSH authentication failed");

    let host_key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519).context("generate SSH host key")?;
    let server_config = Arc::new(server::Config {
        keys: vec![host_key],
        ..Default::default()
    });
    let handler = ProxyServer {
        proxy_username,
        proxy_password,
        target_session,
        target_channels: HashMap::new(),
    };

    server::run_stream(server_config, client_stream, handler)
        .await?
        .await
        .context("run SSH proxy session")
}

struct TargetClient;

impl client::Handler for TargetClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

type TargetChannel = ChannelWriteHalf<client::Msg>;

struct ProxyServer {
    proxy_username: String,
    proxy_password: SecretString,
    target_session: client::Handle<TargetClient>,
    target_channels: HashMap<ChannelId, TargetChannel>,
}

impl ProxyServer {
    fn target_channel(&self, channel: ChannelId) -> anyhow::Result<&TargetChannel> {
        self.target_channels.get(&channel).context("unknown SSH channel")
    }
}

impl server::Handler for ProxyServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<server::Auth, Self::Error> {
        let accepted = user == self.proxy_username && password == self.proxy_password.expose_secret();
        debug!(user, accepted, "SSH proxy password authentication");

        if accepted {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        let downstream_channel = channel.id();
        let target_channel = self.target_session.channel_open_session().await?;
        let (target_reader, target_writer) = target_channel.split();
        self.target_channels.insert(downstream_channel, target_writer);

        let downstream_session = session.handle();
        tokio::spawn(async move {
            if let Err(error) = relay_target_channel(target_reader, downstream_channel, downstream_session).await {
                warn!(?error, ?downstream_channel, "SSH target channel relay failed");
            }
        });

        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?.data(Cursor::new(data.to_vec())).await?;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?
            .extended_data(code, Cursor::new(data.to_vec()))
            .await?;
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, _session: &mut server::Session) -> Result<(), Self::Error> {
        self.target_channel(channel)?.eof().await?;
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut server::Session) -> Result<(), Self::Error> {
        debug!(?channel, "SSH downstream channel close");
        if let Some(target_channel) = self.target_channels.remove(&channel) {
            target_channel.close().await?;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?
            .request_pty(true, term, col_width, row_height, pix_width, pix_height, modes)
            .await?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?
            .set_env(true, variable_name, variable_value)
            .await?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, _session: &mut server::Session) -> Result<(), Self::Error> {
        self.target_channel(channel)?.request_shell(true).await?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?.exec(true, data.to_vec()).await?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?.request_subsystem(true, name).await?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?
            .window_change(col_width, row_height, pix_width, pix_height)
            .await?;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.target_channel(channel)?.signal(signal).await?;
        Ok(())
    }
}

async fn relay_target_channel(
    mut target_reader: ChannelReadHalf,
    downstream_channel: ChannelId,
    downstream_session: server::Handle,
) -> anyhow::Result<()> {
    while let Some(message) = target_reader.wait().await {
        match message {
            ChannelMsg::Data { data } => downstream_session
                .data(downstream_channel, data)
                .await
                .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?,
            ChannelMsg::ExtendedData { data, ext } => downstream_session
                .extended_data(downstream_channel, ext, data)
                .await
                .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?,
            ChannelMsg::Eof => {
                debug!(?downstream_channel, "SSH target channel EOF");
                downstream_session
                    .eof(downstream_channel)
                    .await
                    .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?;
            }
            ChannelMsg::Close => {
                debug!(?downstream_channel, "SSH target channel close");
                downstream_session
                    .close(downstream_channel)
                    .await
                    .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?;
                break;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                debug!(?downstream_channel, exit_status, "SSH target channel exit status");
                downstream_session
                    .exit_status_request(downstream_channel, exit_status)
                    .await
                    .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?;
                downstream_session
                    .close(downstream_channel)
                    .await
                    .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?;
                break;
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                downstream_session
                    .exit_signal_request(downstream_channel, signal_name, core_dumped, error_message, lang_tag)
                    .await
                    .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?;
                downstream_session
                    .close(downstream_channel)
                    .await
                    .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?;
                break;
            }
            ChannelMsg::Success => downstream_session
                .channel_success(downstream_channel)
                .await
                .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?,
            ChannelMsg::Failure => downstream_session
                .channel_failure(downstream_channel)
                .await
                .map_err(|_| anyhow::anyhow!("downstream SSH channel closed"))?,
            _ => {}
        }
    }

    Ok(())
}
