use picky_asn1_der::Asn1DerError;
use std::io::{self, Read, Write};
use std::mem::size_of;

const USIZE_LEN: usize = size_of::<usize>();

pub trait ReadExt {
    fn read_one(&mut self) -> io::Result<u8>;
}

impl<T: Read> ReadExt for T {
    fn read_one(&mut self) -> io::Result<u8> {
        let mut buf = [0];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

pub trait WriteExt {
    fn write_one(&mut self, byte: u8) -> io::Result<usize>;
    fn write_exact(&mut self, data: &[u8]) -> io::Result<usize>;
}

impl<T: Write> WriteExt for T {
    fn write_one(&mut self, byte: u8) -> io::Result<usize> {
        self.write_exact(&[byte])
    }
    fn write_exact(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_all(data)?;
        Ok(data.len())
    }
}

pub struct Length;

impl Length {
    pub fn deserialized(mut reader: impl Read) -> Result<usize, Asn1DerError> {
        Ok(match reader.read_one()? {
            n @ 128..=255 => {
                let len = n as usize & 127;
                if len > USIZE_LEN {
                    return Err(Asn1DerError::UnsupportedValue);
                }

                let mut num = [0; USIZE_LEN];
                reader.read_exact(&mut num[USIZE_LEN - len..])?;
                usize::from_be_bytes(num)
            }
            n => n as usize,
        })
    }

    pub fn serialize(len: usize, mut writer: impl Write) -> Result<usize, Asn1DerError> {
        let written = match len {
            0..=127 => writer.write_one(len as u8)?,
            _ => {
                let to_write = USIZE_LEN - (len.leading_zeros() / 8) as usize;
                let mut written = writer.write_one(to_write as u8 | 0x80)?;

                let mut buf = [0; USIZE_LEN];
                buf.copy_from_slice(&len.to_be_bytes());
                written += writer.write_exact(&buf[USIZE_LEN - to_write..])?;

                written
            }
        };

        Ok(written)
    }

    pub fn encoded_len(len: usize) -> usize {
        match len {
            0..=127 => 1,
            _ => 1 + USIZE_LEN - (len.leading_zeros() / 8) as usize,
        }
    }
}
