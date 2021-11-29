pub mod jet;
pub mod listener;
pub mod pipe;
pub mod proxy;

mod io;
mod utils;

use jmux_proxy::JmuxConfig;
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

        pipe(pipe_a, pipe_b, log.clone()).await.context("Failed to pipe")?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct JmuxProxyCfg {
    pub pipe_mode: pipe::PipeMode,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
    pub listener_modes: Vec<self::listener::ListenerMode>,
    pub jmux_cfg: JmuxConfig,
}

pub async fn jmux_proxy(cfg: JmuxProxyCfg, log: Logger) -> anyhow::Result<()> {
    use self::listener::{socks5_listener_task, tcp_listener_task, ListenerMode};
    use jmux_proxy::JmuxProxy;
    use pipe::open_pipe;
    use tokio::sync::mpsc;

    debug!(log, "Configuration: {:?}", cfg);

    let (api_request_tx, api_request_rx) = mpsc::channel(10);

    for listener_mode in cfg.listener_modes {
        match listener_mode {
            ListenerMode::Tcp {
                bind_addr,
                destination_url,
            } => {
                let listener_log = log.new(o!("TCP listener" => bind_addr.clone()));
                let api_request_tx = api_request_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        tcp_listener_task(api_request_tx, bind_addr, destination_url, listener_log.clone()).await
                    {
                        error!(listener_log, "Task failed: {:?}", e);
                    }
                });
            }
            ListenerMode::Socks5 { bind_addr } => {
                let listener_log = log.new(o!("SOCKS5 listener" => bind_addr.clone()));
                let api_request_tx = api_request_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = socks5_listener_task(api_request_tx, bind_addr, listener_log.clone()).await {
                        error!(listener_log, "Task failed: {:?}", e);
                    }
                });
            }
        }
    }

    // Open generic pipe to exchange JMUX channel messages on
    let pipe_log = log.new(o!("open pipe" => "JMUX pipe"));
    let pipe = open_pipe(cfg.pipe_mode, cfg.proxy_cfg, pipe_log).await?;

    // Start JMUX proxy over the pipe
    JmuxProxy::new(pipe.read, pipe.write)
        .with_config(cfg.jmux_cfg)
        .with_requester_api(api_request_rx)
        .with_logger(log)
        .run()
        .await
}
