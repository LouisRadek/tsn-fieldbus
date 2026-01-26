#![allow(dead_code)]
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor};

pub const ETHERTYPE_L2_PROTOCOL: u16 = 0x88B6;
pub const L2_PROTOCOL_VERSION: u8 = 0x01;
pub const L2_PROTOCOL_FLAGS: u8 = 0x00;
pub const L2_HEADER_SIZE: usize = 6;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Header {
    version: u8,
    stream_id: u16,
    cycle_counter: u16,
    status: u8,
    flags: u8,
}

impl L2Header {
    pub fn new(stream_id: u16, cycle_counter: u16, status: u8) -> Self {
        Self {
            version: L2_PROTOCOL_VERSION,
            stream_id,
            cycle_counter,
            status,
            flags: L2_PROTOCOL_FLAGS,
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.write_u8(self.version)?;
        buf.write_u16::<BigEndian>(self.stream_id)?;
        buf.write_u16::<BigEndian>(self.cycle_counter)?;
        buf.write_u8(self.status)?;
        buf.write_u8(self.flags)?;
        Ok(())
    }

    pub fn read_from(buf: &[u8]) -> io::Result<Self> {
        let mut reader = Cursor::new(buf);
        let version = reader.read_u8()?;
        let stream_id = reader.read_u16::<BigEndian>()?;
        let cycle_counter = reader.read_u16::<BigEndian>()?;
        let status = reader.read_u8()?;
        let flags = reader.read_u8()?;

        Ok(L2Header {
            version,
            stream_id,
            cycle_counter,
            status,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read() {
        let hdr = L2Header::new(0x1234, 0xABCD, 0xEF);
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let expected = vec![
            L2_PROTOCOL_VERSION,
            0x12,
            0x34,
            0xAB,
            0xCD,
            0xEF,
            L2_PROTOCOL_FLAGS,
        ];
        assert_eq!(buf, expected);
        let parsed = L2Header::read_from(&buf).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_read_from_with_extra_bytes() {
        let hdr = L2Header::new(0x0102, 0x0304, 0x05);
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let parsed = L2Header::read_from(&buf).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_read_from_short_buffer_errors() {
        let short = vec![0u8; 5];
        assert!(L2Header::read_from(&short).is_err());
    }
}
