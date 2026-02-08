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
use pnet::util::MacAddr;
use std::io::{self, Cursor};

use crate::slave_api::StatusCode;

pub const ETHERTYPE_L2_PROTOCOL: u16 = 0x88B6;
pub const L2_PROTOCOL_VERSION: u8 = 0x01;
pub const L2_PROTOCOL_FLAGS: u8 = 0x00;
pub const L2_HEADER_SIZE: usize = 7;
pub const VLAN_ETHERTYPE: u16 = 0x8100;
pub const ALLOWED_MULTIPLE_OVER_CYCLE_TIME: f32 = 1.5;

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
    pub version: u8,
    pub stream_id: u16,
    pub cycle_counter: u16,
    pub status: u8,
    pub flags: u8,
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

/// Parsed L2 frame with header and payload view.
#[derive(Debug)]
pub struct ParsedL2Frame<'a> {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub vlan_id_pcp: u16,
    pub header: L2Header,
    pub payload: &'a [u8],
}

pub fn build_l2_frame(
    source: MacAddr,
    destination: MacAddr,
    vlan_id_pcp: u16,
    header: &L2Header,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(18 + L2_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&source.octets());
    frame.write_u16::<BigEndian>(VLAN_ETHERTYPE).unwrap();
    frame.write_u16::<BigEndian>(vlan_id_pcp).unwrap();
    frame
        .write_u16::<BigEndian>(crate::l2_types::ETHERTYPE_L2_PROTOCOL)
        .unwrap();
    header.write_to(&mut frame).unwrap();
    frame.extend_from_slice(payload);
    frame
}

pub fn parse_l2_frame(frame: &[u8]) -> Result<ParsedL2Frame<'_>, StatusCode> {
    if frame.len() < 18 + L2_HEADER_SIZE {
        return Err(StatusCode::ErrInvalidLen);
    }

    let destination = MacAddr::new(frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]);
    let source = MacAddr::new(frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != VLAN_ETHERTYPE {
        return Err(StatusCode::ErrInvalidLen);
    }

    let vlan_id_pcp = u16::from_be_bytes([frame[14], frame[15]]);
    let inner_ethertype = u16::from_be_bytes([frame[16], frame[17]]);
    if inner_ethertype != crate::l2_types::ETHERTYPE_L2_PROTOCOL {
        return Err(StatusCode::ErrInvalidLen);
    }

    let header = L2Header::read_from(&frame[18..18 + L2_HEADER_SIZE])
        .map_err(|_| StatusCode::ErrInvalidLen)?;
    let payload = &frame[18 + L2_HEADER_SIZE..];

    Ok(ParsedL2Frame {
        destination,
        source,
        vlan_id_pcp,
        header,
        payload,
    })
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

    #[test]
    fn test_parse_l2_frame_rejects_short_frame() {
        let short = vec![0u8; 10];
        assert!(parse_l2_frame(&short).is_err());
    }

    #[test]
    fn test_parse_l2_frame_rejects_non_vlan_ethertype() {
        let mut frame = vec![0u8; 18 + L2_HEADER_SIZE];
        frame[12] = 0x12;
        frame[13] = 0x34;
        assert!(matches!(
            parse_l2_frame(&frame),
            Err(StatusCode::ErrInvalidLen)
        ));
    }

    #[test]
    fn test_parse_l2_frame_rejects_non_l2_ethertype() {
        let mut frame = vec![0u8; 18 + L2_HEADER_SIZE];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[16] = 0x12;
        frame[17] = 0x34;
        assert!(matches!(
            parse_l2_frame(&frame),
            Err(StatusCode::ErrInvalidLen)
        ));
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let header = L2Header::new(0x1001, 0x2002, StatusCode::NoError as u8);
        let payload = vec![0xAA, 0xBB, 0xCC];
        let source = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let destination = MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB);
        let vlan_id_pcp = 0x1234;
        let frame = build_l2_frame(source, destination, vlan_id_pcp, &header, &payload);

        let parsed = parse_l2_frame(&frame).expect("frame should parse");
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.source, source);
        assert_eq!(parsed.vlan_id_pcp, vlan_id_pcp);
        assert_eq!(parsed.header, header);
        assert_eq!(parsed.payload, payload.as_slice());
    }
}
