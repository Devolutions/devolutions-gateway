use std::env;
use std::net::IpAddr;

use dns_lookup::lookup_addr;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 || args[1] == "-h" || args[1] == "--help" {
        println!("Usage: {} <IP_ADDRESS>", args[0]);
        return;
    }

    let ip: IpAddr = match args[1].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address.");
            return;
        }
    };

    match lookup_addr(&ip) {
        Ok(hostname) => println!("{hostname}"),
        Err(e) => eprintln!("Lookup failed: {e}"),
    }
}
