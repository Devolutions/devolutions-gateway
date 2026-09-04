#[cfg(windows)]
mod windows;

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    windows::run().await
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("agent policy tester only supports Windows")
}
