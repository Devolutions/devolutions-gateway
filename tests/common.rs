use std::env;
use std::path::PathBuf;
use std::process::{Child, Command};

fn bin() -> PathBuf {
    let mut me = env::current_exe().unwrap();
    me.pop();
    if me.ends_with("deps") {
        me.pop();
    }
    me.push("devolutions-jet");

    me
}

pub struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

pub fn run_proxy(proxy_addr: &str, websocket_url: Option<&str>, routing_url: Option<&str>, identities_file: Option<&str>) -> KillOnDrop {
    let mut proxy_command = Command::new(bin());

    let cmd_line_arg = format!("tcp://{}", proxy_addr);
    proxy_command.arg("--url").arg(cmd_line_arg);

    if let Some(websocket_url) = websocket_url {
        proxy_command.arg("--ws_url").arg(websocket_url);
    }
    if routing_url.is_some() {
        proxy_command.arg("--routing_url").arg(routing_url.unwrap());
    }

    if identities_file.is_some() {
        proxy_command.arg("--identities_file").arg(identities_file.unwrap());
    }

    let proxy = proxy_command.spawn().unwrap();

    println!("Devolutions-Jet is running... (command={:?})", proxy_command);

    KillOnDrop(proxy)
}
