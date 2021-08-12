mod io;
pub mod jet;
pub mod jmux;
pub mod pipe;
pub mod proxy;
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
