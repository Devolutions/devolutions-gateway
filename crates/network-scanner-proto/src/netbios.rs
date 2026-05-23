/// original source: https://github.com/jonkgrimes/nbtscanner/blob/main/Cargo.toml
use std::fmt;
use std::fmt::Display;
use std::net::Ipv4Addr;

const RESPONSE_BASE_LEN: usize = 57;
const RESPONSE_NAME_LEN: usize = 15;
const RESPONSE_NAME_BLOCK_LEN: usize = 18;

pub struct NetBiosPacket<'a> {
    pub ip: Ipv4Addr,
    pub data: &'a [u8],
}

impl Display for NetBiosPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut values = String::new();
        for byte in self.data.iter() {
            values.push_str(&format!("0x{:01$X}, ", byte, 2));
        }
        write!(f, "[{values}]")
    }
}

impl<'a> NetBiosPacket<'a> {
    pub fn from(ip: Ipv4Addr, data: &'a [u8]) -> NetBiosPacket<'a> {
        NetBiosPacket { ip, data }
    }

    pub fn name(&self) -> String {
        let offset = RESPONSE_BASE_LEN + RESPONSE_NAME_LEN;
        let name_range = RESPONSE_BASE_LEN..offset;
        let name_bytes = Vec::from(&self.data[name_range]);

        match String::from_utf8(name_bytes) {
            Ok(name) => String::from(name.trim_end()),
            Err(_) => String::from("N/A"),
        }
    }

    pub fn group(&self) -> Option<String> {
        let offset = RESPONSE_BASE_LEN + RESPONSE_NAME_LEN + 2;
        let block_range = offset..(offset + RESPONSE_NAME_BLOCK_LEN - 1);
        let block_bytes = Vec::from(&self.data[block_range]);

        match String::from_utf8(block_bytes) {
            Ok(group) => {
                let trimmed_group = group.trim_matches('\u{0}').trim_end();
                Some(String::from(trimmed_group))
            }
            Err(_) => None,
        }
    }

    pub fn group_and_name(&self) -> String {
        if let Some(group) = self.group()
            && !group.is_empty()
        {
            return format!("{}\\{}", group, self.name());
        }
        self.name()
    }

    pub fn mac_address(&self) -> String {
        let name_count = self.data[RESPONSE_BASE_LEN - 1] as usize;
        let mut name_bytes: [u8; 6] = [0; 6];
        for (n, byte) in name_bytes.iter_mut().enumerate() {
            let offset = RESPONSE_BASE_LEN + RESPONSE_NAME_BLOCK_LEN * name_count + n;
            *byte = self.data[offset];
        }
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            name_bytes[0], name_bytes[1], name_bytes[2], name_bytes[3], name_bytes[4], name_bytes[5]
        )
    }
}
