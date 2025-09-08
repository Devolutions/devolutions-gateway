// Used by the jetsocat binary.
use {dirs_next as _, humantime as _, seahorse as _, tracing_appender as _, tracing_subscriber as _};

// Used by tests
#[cfg(test)]
use {proptest as _, test_utils as _};

#[macro_use]
extern crate tracing;

pub mod doctor;
pub mod listener;
pub mod pipe;
pub mod proxy;

mod jet;
mod mcp;
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
    use self::listener::{ListenerMode, http_listener_task, socks5_listener_task, tcp_listener_task};
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

    let (reader, writer) = tokio::io::split(pipe.stream);

    // Start JMUX proxy over the pipe
    let proxy_fut = JmuxProxy::new(Box::new(reader), Box::new(writer))
        .with_config(cfg.jmux_cfg)
        .with_requester_api(api_request_rx)
        .run();

    utils::while_process_is_running(cfg.watch_process, proxy_fut).await
}

#[derive(Debug)]
pub struct DoctorCfg {
    pub pipe_mode: pipe::PipeMode,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
    pub pipe_timeout: Option<Duration>,
    pub watch_process: Option<sysinfo::Pid>,
    pub format: DoctorOutputFormat,
    pub args: doctor::Args,
}

#[derive(Debug, Clone, Copy)]
pub enum DoctorOutputFormat {
    Human,
    Json,
}

pub async fn doctor(cfg: DoctorCfg) -> anyhow::Result<()> {
    use pipe::open_pipe;
    use tokio::io::AsyncWriteExt as _;
    use tokio::sync::mpsc;

    info!("Start diagnostics");
    debug!(?cfg);

    let mut pipe = utils::timeout(cfg.pipe_timeout, open_pipe(cfg.pipe_mode, cfg.proxy_cfg))
        .instrument(info_span!("open_jumx_pipe"))
        .await
        .context("couldn't open pipe")?;

    let (tx, mut rx) = mpsc::channel(10);

    let diagnostics_task = tokio::task::spawn_blocking(move || {
        let mut num_failed: u8 = 0;

        doctor::run(cfg.args, &mut |diagnostic| {
            if !diagnostic.success {
                num_failed += 1;
            }

            tx.blocking_send(diagnostic).is_ok()
        });

        num_failed
    });

    let pipe_future = async move {
        while let Some(diagnostic) = rx.recv().await {
            let formatted = match cfg.format {
                DoctorOutputFormat::Human => format!("{}\n\n", diagnostic.human_display()),
                DoctorOutputFormat::Json => format!("{}\n", diagnostic.json_display()),
            };

            pipe.stream
                .write_all(formatted.as_bytes())
                .await
                .context("failed to write diagnostic")?;
        }

        pipe.stream.flush().await.context("failed to flush the stream")?;

        anyhow::Ok(())
    };

    utils::while_process_is_running(cfg.watch_process, pipe_future).await?;

    let num_failed = diagnostics_task.await.context("doctor thread failed")?;

    if num_failed > 0 {
        anyhow::bail!("Found {num_failed} issue(s)");
    }

    Ok(())
}

#[derive(Debug)]
pub struct McpProxyCfg {
    pub pipe_mode: pipe::PipeMode,
    pub pipe_timeout: Option<Duration>,
    pub watch_process: Option<sysinfo::Pid>,
    pub proxy_cfg: Option<proxy::ProxyConfig>,
    pub mcp_proxy_cfg: mcp_proxy::Config,
}

#[instrument(skip_all)]
pub async fn mcp_proxy(cfg: McpProxyCfg) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use pipe::open_pipe;

    info!("Start MCP proxy action");
    debug!(?cfg);

    let pipe = utils::timeout(cfg.pipe_timeout, open_pipe(cfg.pipe_mode, cfg.proxy_cfg))
        .instrument(info_span!("open_mcp_request_pipe"))
        .await
        .context("couldn't open MCP request pipe")?;

    let mcp_proxy = utils::timeout(cfg.pipe_timeout, mcp_proxy::McpProxy::init(cfg.mcp_proxy_cfg))
        .await
        .context("failed to initialize MCP proxy")?;

    let mcp_proxy_fut = mcp::run_mcp_proxy(pipe, mcp_proxy);

    utils::while_process_is_running(cfg.watch_process, mcp_proxy_fut)
        .await
        .context("failed to pipe")?;

    Ok(())
}
