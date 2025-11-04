#![allow(unused_crate_dependencies)]
#![expect(clippy::clone_on_ref_ptr, reason = "example code clarity over performance")]

use std::net::{IpAddr, SocketAddr};

use network_scanner_net::runtime::Socket2Runtime;
use socket2::{Domain, SockAddr, Type};

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async move {
        let runtime = Socket2Runtime::new(None)?;

        let mut futures = vec![];
        for ip in 0..255 {
            let ip: IpAddr = format!("10.10.0.{ip}").parse().unwrap();
            let runtime = runtime.clone();
            let ports = vec![22, 23, 80, 443, 3389];
            for port in ports {
                let socket = runtime.new_socket(Domain::IPV4, Type::STREAM, None)?;
                let addr = SocketAddr::from((ip, port));
                let addr = SockAddr::from(addr);
                let future = async move {
                    socket.connect(&addr).await?;
                    anyhow::Ok(())
                };
                futures.push(future);
            }
        }

        let now = std::time::Instant::now();
        let hanldes: Vec<_> = futures.into_iter().map(|f| tokio::task::spawn(f)).collect();

        for handle in hanldes {
            let _ = handle.await;
        }

        println!("elapsed: {:?}", now.elapsed());

        anyhow::Ok(())
    })?;

    Ok(())
}
