use std::net::{IpAddr, SocketAddr};

use derive_more::From;
use socket2::SockAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedPort {
    Rdp,
    Ard,
    Vnc,
    Ssh,
    Sshpwsh,
    Sftp,
    Scp,
    Telnet,
    WinrmHttpPwsh,
    WinrmHttpsPwsh,
    Http,
    Https,
    Ldap,
    Ldaps,
}

impl Into<u16> for &NamedPort {
    fn into(self) -> u16 {
        match self {
            NamedPort::Rdp => 3389,
            NamedPort::Ard => 5900,
            NamedPort::Vnc => 5900,
            NamedPort::Ssh => 22,
            NamedPort::Sshpwsh => 22,
            NamedPort::Sftp => 22,
            NamedPort::Scp => 22,
            NamedPort::Telnet => 23,
            NamedPort::WinrmHttpPwsh => 5985,
            NamedPort::WinrmHttpsPwsh => 5986,
            NamedPort::Http => 80,
            NamedPort::Https => 443,
            NamedPort::Ldap => 389,
            NamedPort::Ldaps => 636,
        }
    }
}

impl TryFrom<u16> for NamedPort {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            3389 => Ok(NamedPort::Rdp),
            5900 => Ok(NamedPort::Ard), // Note: Same as VNC, will return Ard by convention
            22 => Ok(NamedPort::Ssh),   // Note: Same as Sshpwsh/Sftp/Scp, will return Ssh by convention
            23 => Ok(NamedPort::Telnet),
            5985 => Ok(NamedPort::WinrmHttpPwsh),
            5986 => Ok(NamedPort::WinrmHttpsPwsh),
            80 => Ok(NamedPort::Http),
            443 => Ok(NamedPort::Https),
            389 => Ok(NamedPort::Ldap),
            636 => Ok(NamedPort::Ldaps),
            _ => Err(anyhow::anyhow!("Unknown port number: {}", value)),
        }
    }
}

impl TryFrom<&str> for NamedPort {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "rdp" => Ok(NamedPort::Rdp),
            "ard" => Ok(NamedPort::Ard),
            "vnc" => Ok(NamedPort::Vnc),
            "ssh" => Ok(NamedPort::Ssh),
            "sshpwsh" => Ok(NamedPort::Sshpwsh),
            "sftp" => Ok(NamedPort::Sftp),
            "scp" => Ok(NamedPort::Scp),
            "telnet" => Ok(NamedPort::Telnet),
            "winrmhttppwsh" => Ok(NamedPort::WinrmHttpPwsh),
            "winrmhttpspwsh" => Ok(NamedPort::WinrmHttpsPwsh),
            "http" => Ok(NamedPort::Http),
            "https" => Ok(NamedPort::Https),
            "ldap" => Ok(NamedPort::Ldap),
            "ldaps" => Ok(NamedPort::Ldaps),
            _ => Err(anyhow::anyhow!("Unknown named port: {}", value)),
        }
    }
}

#[derive(Debug, Clone, From)]
pub enum MaybeNamedPort {
    Named(NamedPort),
    Port(u16),
}

impl TryFrom<&str> for MaybeNamedPort {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(port) = value.parse::<u16>() {
            return Ok(MaybeNamedPort::Port(port));
        }

        if let Ok(named_port) = NamedPort::try_from(value) {
            return Ok(MaybeNamedPort::Named(named_port));
        }

        Err(anyhow::anyhow!("Unknown port or named port: {}", value))
    }
}

impl PartialEq for MaybeNamedPort {
    fn eq(&self, other: &Self) -> bool {
        let raw_port = u16::from(self);
        let raw_other_port = u16::from(other);

        raw_port == raw_other_port
    }
}

impl From<&MaybeNamedPort> for u16 {
    fn from(tcp_knock: &MaybeNamedPort) -> Self {
        match tcp_knock {
            MaybeNamedPort::Named(named_port) => named_port.into(),
            MaybeNamedPort::Port(port) => *port,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Probe {
    Ping,
    TcpKnock,
}

#[derive(Debug, Clone)]
pub struct NamedAddress {
    pub ip: IpAddr,
    pub port: MaybeNamedPort,
}

impl AsRef<NamedAddress> for NamedAddress {
    fn as_ref(&self) -> &NamedAddress {
        return self;
    }
}

impl NamedAddress {
    pub fn new(ip: IpAddr, port: MaybeNamedPort) -> Self {
        Self { ip, port }
    }
}

impl From<&NamedAddress> for SockAddr {
    fn from(named_address: &NamedAddress) -> Self {
        let port: u16 = (&named_address.port).into();
        SockAddr::from(SocketAddr::from((named_address.ip, port)))
    }
}

impl From<&SocketAddr> for NamedAddress {
    fn from(addr: &SocketAddr) -> Self {
        Self {
            ip: addr.ip(),
            port: MaybeNamedPort::Port(addr.port()),
        }
    }
}
