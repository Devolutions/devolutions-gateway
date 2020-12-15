mod jet_proto;

use std::{
    io::{self, Read, Write},
    net::{self, TcpStream},
    str,
    sync::{mpsc, Arc, Barrier},
    thread,
};

use structopt::StructOpt;
use uuid::Uuid;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "benchmark")]
struct Opt {
    #[structopt(short = "a", long = "connect")]
    connect_addr: net::SocketAddrV4,
    #[structopt(short, long, default_value = "1024")]
    count: usize,
    #[structopt(long, default_value = "1048576")]
    client_block_size: usize,
    #[structopt(long, default_value = "1048576")]
    server_block_size: usize,
    #[structopt(short, long, default_value = "rw")]
    mode: Mode,
    #[structopt(short, long, default_value = "1")]
    tests: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    Write,
    Read,
    RW,
    Concurrent,
}

impl Mode {
    fn need_read(&self) -> bool {
        *self == Self::Read || *self == Self::RW
    }

    fn need_write(&self) -> bool {
        *self == Self::Write || *self == Self::RW
    }
}

impl str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "write" | "w" => Ok(Self::Write),
            "read" | "r" => Ok(Self::Read),
            "rw" => Ok(Self::RW),
            "concurrent" | "c" => Ok(Self::Concurrent),
            _ => Err("invalid value of mode".to_string()),
        }
    }
}

fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    let (associations_sender, associations_receiver) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let barrier_s = barrier.clone();

    let opt_s = opt.clone();
    let server_handle = thread::Builder::new()
        .name("server".to_string())
        .spawn(move || run_servers(opt_s, associations_sender, barrier_s))?;

    run_clients(opt, associations_receiver, barrier)?;

    server_handle.join().unwrap()?;
    Ok(())
}

fn run_servers(opt: Opt, associations_sender: mpsc::Sender<Uuid>, barrier: Arc<Barrier>) -> io::Result<()> {
    let msg = vec![0; opt.server_block_size];
    let mut buf = vec![0; opt.client_block_size];
    let host = opt.connect_addr.ip().to_string();

    for _ in 0..opt.tests {
        let mut stream = TcpStream::connect(opt.connect_addr)?;
        let association = jet_proto::connect_as_server(&mut stream, host.clone())?;
        associations_sender
            .send(association)
            .expect("failed to send association");
        barrier.wait();

        for _ in 0..opt.count {
            match opt.mode {
                Mode::Concurrent => {
                    stream.write_all(&msg)?;
                    stream.read_exact(&mut buf.as_mut())?;
                }
                _ => {
                    if opt.mode.need_write() {
                        stream.read_exact(&mut buf.as_mut())?;
                    }
                    if opt.mode.need_read() {
                        stream.write_all(&msg)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn run_clients(opt: Opt, associations_receiver: mpsc::Receiver<Uuid>, barrier: Arc<Barrier>) -> std::io::Result<()> {
    let msg = vec![0; opt.client_block_size];
    let mut buf = vec![0; opt.server_block_size];
    let host = opt.connect_addr.ip().to_string();

    let total_time_ms: u128 = (0..opt.tests)
        .map(|i| {
            let mut stream = std::net::TcpStream::connect(opt.connect_addr).unwrap();
            let association = associations_receiver.recv().expect("failed to receive association");
            jet_proto::connect_as_client(&mut stream, host.clone(), association).expect("failed to connect as client");
            barrier.wait();

            let now = std::time::Instant::now();
            for _ in 0..opt.count {
                match opt.mode {
                    Mode::Concurrent => {
                        stream.write_all(&msg).unwrap();
                        stream.read_exact(&mut buf.as_mut()).unwrap();
                    }
                    _ => {
                        if opt.mode.need_write() {
                            stream.write_all(&msg).unwrap();
                        }
                        if opt.mode.need_read() {
                            stream.read_exact(&mut buf.as_mut()).unwrap();
                        }
                    }
                }
            }
            let elapsed = now.elapsed().as_millis();
            println!("Test {}: {}ms", i, elapsed);
            elapsed
        })
        .sum();

    println!("Average: {}ms", (total_time_ms as f64) / (opt.tests as f64));

    Ok(())
}
