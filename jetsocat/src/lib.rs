pub mod jet;
pub mod listener;
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

        pipe(pipe_a, pipe_b, log.clone()).await.context("Failed to pipe")?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct JmuxProxyCfg {
    pub pipe_mode: pipe::PipeMode,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
    pub listener_modes: Vec<self::listener::ListenerMode>,
}

pub async fn jmux_proxy(cfg: JmuxProxyCfg, log: Logger) -> anyhow::Result<()> {
    use self::listener::{socks5_listener_task, tcp_listener_task, ListenerMode};
    use pipe::open_pipe;
    use tokio::sync::mpsc;

    let (request_sender, request_receiver) = mpsc::unbounded_channel();

    for listener_mode in cfg.listener_modes {
        match listener_mode {
            ListenerMode::Tcp {
                bind_addr,
                destination_url,
            } => {
                let listener_log = log.new(o!("TCP listener" => bind_addr.clone()));
                let request_sender = request_sender.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        tcp_listener_task(request_sender, bind_addr, destination_url, listener_log.clone()).await
                    {
                        error!(listener_log, "Task failed: {:?}", e);
                    }
                });
            }
            ListenerMode::Socks5 { bind_addr } => {
                let listener_log = log.new(o!("SOCKS5 listener" => bind_addr.clone()));
                let request_sender = request_sender.clone();
                tokio::spawn(async move {
                    if let Err(e) = socks5_listener_task(request_sender, bind_addr, listener_log.clone()).await {
                        error!(listener_log, "Task failed: {:?}", e);
                    }
                });
            }
        }
    }

    // Open generic pipe to exchange JMUX channel messages on
    let pipe_log = log.new(o!("open pipe" => "JMUX pipe"));
    let pipe = open_pipe(cfg.pipe_mode, cfg.proxy_cfg, pipe_log).await?;

    // Start JMUX proxy over this pipe
    jmux_proxy::start(request_sender, request_receiver, pipe.read, pipe.write, log).await
}
