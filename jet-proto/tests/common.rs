use std::{
    env,
    path::PathBuf,
    process::{Child, Command},
};

fn bin() -> PathBuf {
    let mut me = env::current_exe().unwrap();
    me.pop();
    if me.ends_with("deps") {
        me.pop();
    }
    me.push("devolutions-gateway");

    me
}

pub struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

pub fn run_proxy(
    proxy_addr: &str,
    websocket_url: Option<&str>,
    routing_url: Option<&str>,
    identities_file: Option<&str>,
) -> KillOnDrop {
    let mut proxy_command = Command::new(bin());

    proxy_command
        .env("RUST_LOG", "DEBUG")
        .args(&["--listener", format!("tcp://{}", proxy_addr).as_str()]);

    if let Some(websocket_url) = websocket_url {
        proxy_command.arg("-l").arg(websocket_url);
    }

    if let Some(url) = routing_url {
        proxy_command.args(&["--routing-url", url]);
    }

    if let Some(file) = identities_file {
        proxy_command.args(&["--identities-file", file]);
    }

    let proxy = proxy_command.spawn().unwrap();

    println!("Devolutions-Gateway is running... (command={:?})", proxy_command);

    KillOnDrop(proxy)
}
