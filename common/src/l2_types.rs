#![allow(dead_code)]
//! L2 Protocol Header Types and Message Handling
//!
//! This module provides types and utilities for working with the L2 protocol, which handles data transmission over Ethernet.
//!
//! # Overview
//!
//! The L2 protocol operates at the Ethernet layer and supports:
//! - Cyclic data transmission
//! - Stream identification and tracking
//! - Data freshness checking through the cycle counter
//! - Data integrity
//!
//! # Protocol Structure
//!
//! TSN L2 messages consist of:
//! 1. **L2 Header** - Contains version, stream ID, cycle counter, status, and flags
//! 2. **Payload** - Data associated with the stream
//! 3. **Auth** - Contains the Authentication Tag and Sequence Number
//!
//! # Example
//!
//! ```no_run
//! use common::l2_types::{L2Header, L2_PROTOCOL_VERSION};
//!
//! // Create an L2 header for stream 1, cycle 0
//! let header = L2Header::new(1, 0, 0x00);
//!
//! // Serialize to bytes
//! let mut buffer = Vec::new();
//! header.write_to(&mut buffer).unwrap();
//! ```

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor};

/// EtherType value for TSN L2 protocol frames
pub const ETHERTYPE_L2_PROTOCOL: u16 = 0x88B6;
/// TSN L2 protocol version (currently 0x01)
pub const L2_PROTOCOL_VERSION: u8 = 0x01;
/// Default flags for L2 headers
pub const L2_PROTOCOL_FLAGS: u8 = 0x00;
/// Fixed size of the L2 header in bytes
pub const L2_HEADER_SIZE: usize = 7;

/// L2 protocol message header
///
/// Contains metadata: version, stream identifier,
/// cycle counter for data freshness checking, status, and flags.
/// This is a 7-byte fixed-size header that appears at the start of all L2 messages.
///
/// # Memory Layout (C struct)
/// ```text
/// Byte 0: Version
/// Bytes 1-2: Stream ID (big-endian)
/// Bytes 3-4: Cycle Counter (big-endian)
/// Byte 5: Status
/// Byte 6: Flags
/// ```
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
    /// Create a new L2 header with the specified stream ID, cycle counter, and status
    ///
    /// # Arguments
    /// * `stream_id` - Unique identifier for the data stream
    /// * `cycle_counter` - Synchronization counter incremented each cycle
    /// * `status` - Status byte indicating header/stream state
    pub fn new(stream_id: u16, cycle_counter: u16, status: u8) -> Self {
        Self {
            version: L2_PROTOCOL_VERSION,
            stream_id,
            cycle_counter,
            status,
            flags: L2_PROTOCOL_FLAGS,
        }
    }

    /// Serialize this header to a byte buffer in big-endian format
    ///
    /// # Errors
    /// Returns `io::Error` if writing to the buffer fails
    pub fn write_to(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.write_u8(self.version)?;
        buf.write_u16::<BigEndian>(self.stream_id)?;
        buf.write_u16::<BigEndian>(self.cycle_counter)?;
        buf.write_u8(self.status)?;
        buf.write_u8(self.flags)?;
        Ok(())
    }

    /// Deserialize a header from a byte buffer in big-endian format
    ///
    /// # Arguments
    /// * `buf` - Buffer containing at least 7 bytes of header data
    ///
    /// # Errors
    /// Returns `io::Error` if the buffer is too small or reading fails
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
