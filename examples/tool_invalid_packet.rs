use std::env;
use std::io::Write;
use std::net::TcpStream;
use std::process;

type Port = u16;

struct Program {
    name: String,
}

impl Program {
    fn new(name: String) -> Program {
        Program { name }
    }

    fn usage(&self) {
        println!("usage: {} HOST PORT", self.name);
    }

    fn print_error(&self, mesg: String) {
        eprintln!("{}: error: {}", self.name, mesg);
    }

    #[allow(dead_code)]
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

    loop {
        let mut stream = TcpStream::connect((host.as_str(), port)).unwrap();
        stream.write_all("This is junk".as_bytes()).unwrap();
    }
}
