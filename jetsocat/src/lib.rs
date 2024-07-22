// Used by the jetsocat binary.
use {dirs_next as _, humantime as _, seahorse as _, tracing_appender as _, tracing_subscriber as _};

// Used by tests
#[cfg(test)]
use {proptest as _, test_utils as _};

#[macro_use]
extern crate tracing;

pub mod listener;
pub mod pipe;
pub mod proxy;

mod jet;
mod process_watcher;
mod utils;

use anyhow::Context as _;
use core::time::Duration;
use jmux_proxy::JmuxConfig;
use tracing::Instrument as _;

#[derive(Debug)]
pub struct ForwardCfg {
    pub pipe_a_mode: pipe::PipeMode,
    pub pipe_b_mode: pipe::PipeMode,
    pub repeat_count: usize,
    pub pipe_timeout: Option<Duration>,
    pub watch_process: Option<sysinfo::Pid>,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
}

#[instrument(skip_all)]
pub async fn forward(cfg: ForwardCfg) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use pipe::{open_pipe, pipe};

    info!("Start forwarding action");
    debug!(?cfg);

    for count in 0..=cfg.repeat_count {
        debug!("Repeat count {}/{}", count, cfg.repeat_count);

        let pipe_a = utils::timeout(
            cfg.pipe_timeout,
            open_pipe(cfg.pipe_a_mode.clone(), cfg.proxy_cfg.clone()),
        )
        .instrument(info_span!("open_pipe_a"))
        .await
        .context("couldn't open pipe A")?;

        let pipe_b = utils::timeout(
            cfg.pipe_timeout,
            open_pipe(cfg.pipe_b_mode.clone(), cfg.proxy_cfg.clone()),
        )
        .instrument(info_span!("open_pipe_b"))
        .await
        .context("couldn't open pipe B")?;

        let pipe_fut = pipe(pipe_a, pipe_b);

        utils::while_process_is_running(cfg.watch_process, pipe_fut)
            .await
            .context("failed to pipe")?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct JmuxProxyCfg {
    pub pipe_mode: pipe::PipeMode,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
    pub listener_modes: Vec<listener::ListenerMode>,
    pub pipe_timeout: Option<Duration>,
    pub watch_process: Option<sysinfo::Pid>,
    pub jmux_cfg: JmuxConfig,
}

#[instrument("jmux", skip_all)]
pub async fn jmux_proxy(cfg: JmuxProxyCfg) -> anyhow::Result<()> {
    use self::listener::{http_listener_task, socks5_listener_task, tcp_listener_task, ListenerMode};
    use jmux_proxy::JmuxProxy;
    use pipe::open_pipe;
    use tokio::sync::mpsc;

    info!("Start JMUX proxy");
    debug!(?cfg);

    let (api_request_tx, api_request_rx) = mpsc::channel(10);

    for listener_mode in cfg.listener_modes {
        match listener_mode {
            ListenerMode::Tcp {
                bind_addr,
                destination_url,
            } => {
                let api_request_tx = api_request_tx.clone();
                tokio::spawn(tcp_listener_task(api_request_tx, bind_addr, destination_url));
            }
            ListenerMode::Http { bind_addr } => {
                let api_request_tx = api_request_tx.clone();
                tokio::spawn(http_listener_task(api_request_tx, bind_addr));
            }
            ListenerMode::Socks5 { bind_addr } => {
                let api_request_tx = api_request_tx.clone();
                tokio::spawn(socks5_listener_task(api_request_tx, bind_addr));
            }
        }
    }

    // Open generic pipe to exchange JMUX channel messages on
    let pipe = utils::timeout(cfg.pipe_timeout, open_pipe(cfg.pipe_mode, cfg.proxy_cfg))
        .instrument(info_span!("open_jumx_pipe"))
        .await
        .context("couldn't open pipe")?;

    // Start JMUX proxy over the pipe
    let proxy_fut = JmuxProxy::new(pipe.read, pipe.write)
        .with_config(cfg.jmux_cfg)
        .with_requester_api(api_request_rx)
        .run();

    utils::while_process_is_running(cfg.watch_process, proxy_fut).await
}
