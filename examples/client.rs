#![allow(unused_variables)]
#![allow(unused_imports)]
extern crate byteorder;
extern crate jet_proto;
extern crate uuid;

use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use jet_proto::{JetMethod, JetPacket};
use std::env;
use std::io::{self, Error, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::process;
use std::str::FromStr;
use std::thread;
use uuid::Uuid;

type Port = u16;

struct Program {
    name: String,
}

impl Program {
    fn new(name: String) -> Program {
        Program { name }
    }

    fn usage(&self) {
        println!("usage: {} HOST PORT [UUID]", self.name);
    }

    fn print_error(&self, mesg: String) {
        writeln!(io::stderr(), "{}: error: {}", self.name, mesg).unwrap();
    }

    fn print_fail(&self, mesg: String) -> ! {
        self.print_error(mesg);
        self.fail();
    }

    fn exit(&self, status: i32) -> ! {
        process::exit(status);
    }
    fn fail(&self) -> ! {
        self.exit(-1);
    }
}

fn main() {
    let mut args = env::args();
    let program = Program::new(args.next().unwrap_or_else(|| "test".to_string()));

    let host = args.next().unwrap_or_else(|| {
        program.usage();
        program.fail();
    });

    let port = args
        .next()
        .unwrap_or_else(|| {
            program.usage();
            program.fail();
        })
        .parse::<Port>()
        .unwrap_or_else(|error| {
            program.print_error(format!("invalid port number: {}", error));
            program.usage();
            program.fail();
        });

    let server_uuid = args
        .next()
        .map(|uuid| {
            Uuid::from_str(&uuid).map(Some).unwrap_or_else(|e| {
                program.print_error(format!("invalid UUID: {}", e));
                program.usage();
                program.fail();
            })
        })
        .unwrap_or_else(|| None);

    let mut stream =
        TcpStream::connect((host.as_str(), port)).unwrap_or_else(|error| program.print_fail(error.to_string()));
    let mut input_stream = stream.try_clone().unwrap();

    let handler = thread::spawn(move || {
        let mut client_buffer = [0u8; 1024];
        let mut jet_packet_received = false;

        loop {
            match input_stream.read(&mut client_buffer) {
                Ok(n) => {
                    if n == 0 {
                        program.exit(0);
                    } else {
                        // Skip header because it is binary
                        let buffer = if jet_packet_received {
                            &client_buffer[0..n]
                        } else {
                            jet_packet_received = true;
                            &client_buffer[8..n]
                        };
                        io::stdout().write_all(&buffer).unwrap();
                        io::stdout().flush().unwrap();
                    }
                }
                Err(error) => program.print_fail(error.to_string()),
            }
        }
    });

    let output_stream = &mut stream;
    let mut user_buffer = String::new();

    let mut jet_packet = JetPacket::new(0, 0);
    jet_packet.set_version(Some(0));
    if let Some(uuid) = server_uuid {
        jet_packet.set_method(Some(JetMethod::CONNECT));
        jet_packet.set_association(Some(uuid));
    } else {
        jet_packet.set_method(Some(JetMethod::ACCEPT));
    }
    let mut v: Vec<u8> = Vec::new();
    jet_packet.write_to(&mut v).unwrap();
    println!("jet_packet = {:?}", jet_packet);
    output_stream.write_all(&v).unwrap();
    output_stream.flush().unwrap();

    loop {
        user_buffer.clear();
        io::stdin().read_line(&mut user_buffer).unwrap();
        output_stream.write_all(user_buffer.as_bytes()).unwrap();
        output_stream.flush().unwrap();
    }
}
