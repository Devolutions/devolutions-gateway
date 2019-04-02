extern crate byteorder;
extern crate jet_proto;
extern crate uuid;

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

pub fn run_proxy(proxy_addr: &str, routing_url: Option<&str>, identities_file: Option<&str>) -> KillOnDrop {
    let mut proxy_command = Command::new(bin());

    let cmd_line_arg = format!("-urltcp://{}", proxy_addr);
    proxy_command.arg(cmd_line_arg);

    if routing_url.is_some() {
        proxy_command.arg("--routing_url").arg(routing_url.unwrap());
    }

    if identities_file.is_some() {
        proxy_command.arg("--identities_file").arg(identities_file.unwrap());
    }

    let proxy = proxy_command.spawn().unwrap();

    KillOnDrop(proxy)
}
