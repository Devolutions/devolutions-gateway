pub mod jet;
pub mod jmux;
pub mod pipe;
pub mod proxy;

mod io;
mod utils;

use slog::*;

#[derive(Debug)]
pub struct ForwardCfg {
    pub pipe_a_mode: pipe::PipeMode,
    pub pipe_b_mode: pipe::PipeMode,
    pub repeat_count: usize,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
}

pub async fn forward(cfg: ForwardCfg, log: Logger) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use pipe::{open_pipe, pipe};

    debug!(log, "Configuration: {:?}", cfg);

    for count in 0..=cfg.repeat_count {
        debug!(log, "Repeat count {}/{}", count, cfg.repeat_count);

        let pipe_a_log = log.new(o!("open pipe" => "A"));
        let pipe_a = open_pipe(cfg.pipe_a_mode.clone(), cfg.proxy_cfg.clone(), pipe_a_log).await?;

        let pipe_b_log = log.new(o!("open pipe" => "B"));
        let pipe_b = open_pipe(cfg.pipe_b_mode.clone(), cfg.proxy_cfg.clone(), pipe_b_log).await?;

        pipe(pipe_a, pipe_b, log.clone())
            .await
            .with_context(|| "Failed to pipe")?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct JmuxProxyCfg {
    pub pipe_mode: pipe::PipeMode,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
    pub listener_modes: Vec<jmux::listener::ListenerMode>,
}

pub async fn jmux_proxy(cfg: JmuxProxyCfg, log: Logger) -> anyhow::Result<()> {
    use self::jmux::listener::{tcp_listener_task, ListenerMode};
    use tokio::sync::mpsc;

    let (jmux_api_request_sender, jmux_api_request_receiver) = mpsc::unbounded_channel();

    for listener_mode in cfg.listener_modes {
        match listener_mode {
            ListenerMode::Tcp {
                bind_addr,
                destination_url,
            } => {
                let listener_log = log.new(o!("TCP listener" => bind_addr.clone()));
                let jmux_api_request_sender = jmux_api_request_sender.clone();
                tokio::spawn(async move {
                    tcp_listener_task(jmux_api_request_sender, bind_addr, destination_url, listener_log).await
                });
            }
            ListenerMode::Socks5 { .. } => anyhow::bail!("SOCKS5 listener is not supported yet"),
        }
    }

    self::jmux::start_proxy(
        jmux_api_request_sender,
        jmux_api_request_receiver,
        cfg.pipe_mode,
        cfg.proxy_cfg,
        log,
    )
    .await
}
