mod graphics;
mod input;
mod tls;

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use ironrdp::server::RdpServer;
use tokio::sync::oneshot;

use crate::config::ConfHandle;

pub(crate) struct RemoteDesktopTask {
    conf_handle: ConfHandle,
}

impl RemoteDesktopTask {
    pub(crate) fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for RemoteDesktopTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "remote desktop";

    async fn run(self, shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();

        std::thread::spawn(move || {
            // FIXME(@CBenoit): make RdpServer implement `Send`

            let res = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("couldn’t build tokio runtime")
                .and_then(|rt| rt.block_on(recording_server_task(self.conf_handle, shutdown_signal)));

            let _ = tx.send(res);
        });

        rx.await
            .context("couldn’t retrieve result from remote desktop server task")?
    }
}

#[instrument(skip_all)]
async fn recording_server_task(conf_handle: ConfHandle, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
    let conf = conf_handle.get_conf();

    let input_handler = input::InputHandler::new();
    let display_handler = graphics::DisplayHandler::new();

    let tls_acceptor = conf
        .remote_desktop
        .certificate
        .as_ref()
        .zip(conf.remote_desktop.private_key.as_ref())
        .map(|(cert, key)| tls::acceptor(cert, key))
        .transpose()
        .context("failed to create TLS acceptor")?;

    let bind_address = conf
        .remote_desktop
        .bind_addresses
        .first() // FIXME(@CBenoit): proper support for multiple bind addresses
        .context("no bind address configured")?;

    let server = RdpServer::builder().with_addr(*bind_address);

    let server = if let Some(tls_acceptor) = tls_acceptor {
        server.with_tls(tls_acceptor)
    } else {
        server.with_no_security()
    };

    let mut server = server
        .with_input_handler(input_handler)
        .with_display_handler(display_handler)
        .build();

    info!(%bind_address, "Remote Desktop Server ready");

    tokio::select! {
        res = server.run() => {
            res.context("remote server failure")?;
        },
        _ = shutdown_signal.wait() => {
            // FIXME(@CBenoit): add graceful shutdown of the RDP server and look into TLS close_notify
            // See: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
            trace!("Received shutdown signal");
        },
    }

    debug!("Task terminated");

    Ok(())
}
