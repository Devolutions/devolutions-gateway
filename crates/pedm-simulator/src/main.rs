#[cfg_attr(windows, path = "windows.rs")]
#[cfg_attr(unix, path = "unix.rs")]
mod imp;

fn main() -> anyhow::Result<()> {
    imp::main()
}
