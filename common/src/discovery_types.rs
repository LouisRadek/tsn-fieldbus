//! SDCP (Service Discovery Control Protocol) Types and Message Handling
//!
//! This module provides types and utilities for working with the SDCP protocol,
//! which is used for device discovery and IP configuration in TSN fieldbus networks.
//!
//! # Overview
//!
//! The SDCP protocol operates at the Ethernet layer and supports:
//! - Device discovery via broadcast
//! - IP address configuration (manual, DHCP, or SDCP-assigned)
//! - Device status reporting
//! - IP configuration reporting
//!
//! # Protocol Structure
//!
//! SDCP messages consist of:
//! 1. **SDCP Header** - Contains version, operation code, transaction ID, and flags
//! 2. **TLV Payloads** - Type-Length-Value encoded data for specific information
//!
//! # Example
//!
//! ```no_run
//! use common::discovery_types::{SdcpHeader, SdcpOpCode, Tlv};
//!
//! // Create a discovery request header
//! let header = SdcpHeader::new(SdcpOpCode::DiscoverReq, 1);
//!
//! // Create device info TLV
//! let tlv = Tlv::device_info(0x1234, 0x5678, 0xDEADBEEF);
//!
//! // Serialize to bytes
//! let mut buffer = Vec::new();
//! header.write_to(&mut buffer).unwrap();
//! tlv.write_to(&mut buffer).unwrap();
//! ```

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use pnet::util::MacAddr;
use std::io::{self, Cursor, Read};

use crate::security::auth_footer::{SecurityFooter, split_payload_and_footer};
use crate::slave_api::{IpSource, StatusCode};

pub const ETHERTYPE_SDCP: u16 = 0x88B5;
pub const SDCP_VERSION: u8 = 0x01;
pub const SDCP_HEADER_SIZE: u8 = 5;
pub const SDCP_FLAGS: u8 = 0x00;
pub const TLV_TYPE_DEVICE_INFO: u8 = 0x01;
pub const TLV_TYPE_IP_CONFIG: u8 = 0x02;
pub const TLV_TYPE_STATUS_REPORT: u8 = 0x03;
pub const TLV_TYPE_IP_REPORT: u8 = 0x04;

/// SDCP operation codes specifying the type of message
///
/// This enum represents all possible SDCP message types:
/// - `DiscoverReq/Res`: Device discovery protocol
/// - `SetIpReq/Res`: Configure IP settings via SDCP
/// - `GetIpReq/Res`: Query current IP settings
/// - `ActivateDhcpReq/Res`: Enable DHCP on device
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SdcpOpCode {
    DiscoverReq = 0x01,
    DiscoverRes = 0x02,
    SetIpReq = 0x03,
    SetIpRes = 0x04,
    GetIpReq = 0x05,
    GetIpRes = 0x06,
    ActivateDhcpReq = 0x07,
    ActivateDhcpRes = 0x08,
    UnknownOperation = 0x09,
}

impl From<u8> for SdcpOpCode {
    fn from(val: u8) -> Self {
        match val {
            0x01 => SdcpOpCode::DiscoverReq,
            0x02 => SdcpOpCode::DiscoverRes,
            0x03 => SdcpOpCode::SetIpReq,
            0x04 => SdcpOpCode::SetIpRes,
            0x05 => SdcpOpCode::GetIpReq,
            0x06 => SdcpOpCode::GetIpRes,
            0x07 => SdcpOpCode::ActivateDhcpReq,
            0x08 => SdcpOpCode::ActivateDhcpRes,
            _ => SdcpOpCode::UnknownOperation,
        }
    }
}

/// SDCP message header
///
/// Contains protocol metadata: version, operation code, transaction ID, and flags.
/// This is a 5-byte fixed-size header that appears at the start of all SDCP messages.
///
/// # Memory Layout (C struct)
/// ```text
/// Byte 0: Version
/// Byte 1: Operation Code
/// Bytes 2-3: Transaction ID (big-endian)
/// Byte 4: Flags
/// ```
#[repr(C, packed)]
#[derive(Debug)]
pub struct SdcpHeader {
    pub version: u8,
    pub op_code: SdcpOpCode,
    pub transaction_id: u16,
    pub flags: u8,
}

impl SdcpHeader {
    /// Create a new SDCP header with the specified operation code and transaction ID
    ///
    /// # Arguments
    /// * `op_code` - The operation to perform
    /// * `transaction_id` - Unique identifier for correlating requests and responses
    pub fn new(op_code: SdcpOpCode, transaction_id: u16) -> Self {
        Self {
            version: SDCP_VERSION,
            op_code,
            transaction_id,
            flags: SDCP_FLAGS,
        }
    }

    /// Serialize this header to a byte buffer in big-endian format
    ///
    /// # Errors
    /// Returns `io::Error` if writing to the buffer fails
    pub fn write_to(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.write_u8(self.version)?;
        buf.write_u8(self.op_code as u8)?;
        buf.write_u16::<BigEndian>(self.transaction_id)?;
        buf.write_u8(self.flags)?;
        Ok(())
    }

    /// Deserialize a header from a byte buffer in big-endian format
    ///
    /// # Arguments
    /// * `buf` - Buffer containing at least 5 bytes of header data
    ///
    /// # Errors
    /// Returns `io::Error` if the buffer is too small or reading fails
    pub fn read_from(buf: &[u8]) -> io::Result<Self> {
        let mut reader = Cursor::new(buf);
        let version = reader.read_u8()?;
        let op_code = reader.read_u8()?.into();
        let transaction_id = reader.read_u16::<BigEndian>()?;
        let flags = reader.read_u8()?;

        Ok(SdcpHeader {
            version,
            op_code,
            transaction_id,
            flags,
        })
    }
}

/// Represents a discovered device with its network and identification information
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub mac_address: MacAddr,
    pub vendor_id: u16,
    pub device_id: u16,
    pub serial_number: u32,
}

impl DiscoveredDevice {
    pub fn new(mac_address: MacAddr, device_info: DeviceInfo) -> Self {
        Self {
            mac_address,
            vendor_id: device_info.vendor_id,
            device_id: device_info.device_id,
            serial_number: device_info.serial_number,
        }
    }
}

/// Device identification information
///
/// Contains basic identification data about an SDCP device
#[derive(Debug)]
pub struct DeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub serial_number: u32,
}

/// IP network configuration parameters
///
/// Specifies the IP address, subnet mask, and default gateway for a device
#[derive(Debug)]
pub struct IpConfig {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
}

/// Device status information
///
/// Reports the current operational status of a device
#[derive(Debug)]
pub struct StatusReport {
    pub status_code: u8,
}

/// Current IP configuration of a device including its source
///
/// Reports the device's current IP settings and how they were assigned
#[derive(Debug)]
pub struct IpReport {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub ip_source: IpSource,
}

/// Type-Length-Value (TLV) encoded data structure
///
/// A generic container for SDCP message payloads. TLV encoding allows flexible,
/// extensible message formats where each field is self-describing.
///
/// # Structure
/// - **Type** (1 byte): Identifies the kind of data (see TLV_TYPE_* constants)
/// - **Length** (1 byte): Size of the value in bytes
/// - **Value** (variable): The actual data payload
#[derive(Debug)]
pub struct Tlv {
    pub t_type: u8,
    pub length: u8,
    value: Vec<u8>,
}

impl Tlv {
    /// Create a new TLV with the specified type and value data
    ///
    /// # Arguments
    /// * `t_type` - TLV type identifier
    /// * `value` - The payload bytes
    ///
    /// The length is automatically calculated from the value size
    pub fn new(t_type: u8, value: Vec<u8>) -> Self {
        Self {
            t_type,
            length: value.len() as u8,
            value,
        }
    }

    /// Create a device info TLV
    ///
    /// # Arguments
    /// * `vendor_id` - Vendor/manufacturer identifier
    /// * `device_id` - Device model identifier
    /// * `serial_number` - Unique device serial number
    pub fn device_info(vendor_id: u16, device_id: u16, serial_number: u32) -> Self {
        let mut value = Vec::with_capacity(8);
        value.extend_from_slice(&vendor_id.to_be_bytes());
        value.extend_from_slice(&device_id.to_be_bytes());
        value.extend_from_slice(&serial_number.to_be_bytes());
        Tlv::new(TLV_TYPE_DEVICE_INFO, value)
    }

    /// Create an IP configuration TLV
    ///
    /// # Arguments
    /// * `ip` - IPv4 address as 4-byte array
    /// * `netmask` - Subnet mask as 4-byte array
    /// * `gateway` - Default gateway address as 4-byte array
    pub fn ip_config(ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> Self {
        let mut value = Vec::with_capacity(12);
        value.extend_from_slice(&ip);
        value.extend_from_slice(&netmask);
        value.extend_from_slice(&gateway);
        Tlv::new(TLV_TYPE_IP_CONFIG, value)
    }

    /// Create a status report TLV
    ///
    /// # Arguments
    /// * `status_code` - The device status code
    pub fn status_report(status_code: StatusCode) -> Self {
        Tlv::new(TLV_TYPE_STATUS_REPORT, vec![status_code as u8])
    }

    /// Create an IP report TLV (current IP configuration with source)
    ///
    /// # Arguments
    /// * `ip` - IPv4 address as 4-byte array
    /// * `netmask` - Subnet mask as 4-byte array
    /// * `gateway` - Default gateway address as 4-byte array
    /// * `ip_source` - How the IP address was assigned
    pub fn ip_report(ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4], ip_source: IpSource) -> Self {
        let mut value = Vec::with_capacity(13);
        value.extend_from_slice(&ip);
        value.extend_from_slice(&netmask);
        value.extend_from_slice(&gateway);
        value.push(ip_source as u8);
        Tlv::new(TLV_TYPE_IP_REPORT, value)
    }

    /// Serialize this TLV to bytes in the format: Type, Length, Value...
    ///
    /// # Errors
    /// Returns `io::Error` if writing to the buffer fails
    pub fn write_to(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.write_u8(self.t_type)?;
        buf.write_u8(self.length)?;
        buf.extend_from_slice(&self.value);
        Ok(())
    }

    /// Deserialize a TLV from bytes
    ///
    /// # Arguments
    /// * `buf` - Buffer containing at least 2 + length bytes
    ///
    /// # Errors
    /// Returns `io::Error` if the buffer is too small or reading fails
    pub fn read_from(buf: &[u8]) -> io::Result<Self> {
        let mut reader = Cursor::new(buf);
        let t_type = reader.read_u8()?;
        let length = reader.read_u8()?;
        let mut value = vec![0u8; length as usize];
        reader.read_exact(&mut value)?;
        Ok(Tlv {
            t_type,
            length,
            value,
        })
    }

    /// Parse device info from this TLV
    ///
    /// Returns `None` if this TLV is not a device info type or has invalid size
    pub fn parse_device_info(&self) -> Option<DeviceInfo> {
        if self.t_type != TLV_TYPE_DEVICE_INFO || self.value.len() != 8 {
            return None;
        }

        let vendor_id = u16::from_be_bytes([self.value[0], self.value[1]]);
        let device_id = u16::from_be_bytes([self.value[2], self.value[3]]);
        let serial_number =
            u32::from_be_bytes([self.value[4], self.value[5], self.value[6], self.value[7]]);

        Some(DeviceInfo {
            vendor_id,
            device_id,
            serial_number,
        })
    }

    /// Parse IP configuration from this TLV
    ///
    /// Returns `None` if this TLV is not an IP config type or has invalid size
    pub fn parse_ip_config(&self) -> Option<IpConfig> {
        if self.t_type != TLV_TYPE_IP_CONFIG || self.value.len() != 12 {
            return None;
        }

        let mut ip = [0u8; 4];
        let mut netmask = [0u8; 4];
        let mut gateway = [0u8; 4];
        ip.copy_from_slice(&self.value[0..4]);
        netmask.copy_from_slice(&self.value[4..8]);
        gateway.copy_from_slice(&self.value[8..12]);

        Some(IpConfig {
            ip,
            netmask,
            gateway,
        })
    }

    /// Parse status report from this TLV
    ///
    /// Returns `None` if this TLV is not a status report type or has invalid size
    pub fn parse_status_report(&self) -> Option<StatusCode> {
        if self.t_type != TLV_TYPE_STATUS_REPORT || self.value.len() != 1 {
            return None;
        }

        StatusCode::try_from(self.value[0] as i32).ok()
    }

    /// Parse IP report from this TLV
    ///
    /// Returns `None` if this TLV is not an IP report type or has invalid size
    pub fn parse_ip_report(&self) -> Option<IpReport> {
        if self.t_type != TLV_TYPE_IP_REPORT || self.value.len() != 13 {
            return None;
        }

        let mut ip = [0u8; 4];
        let mut netmask = [0u8; 4];
        let mut gateway = [0u8; 4];
        ip.copy_from_slice(&self.value[0..4]);
        netmask.copy_from_slice(&self.value[4..8]);
        gateway.copy_from_slice(&self.value[8..12]);
        let ip_source = IpSource::try_from(self.value[12] as i32).unwrap_or_default();

        Some(IpReport {
            ip,
            netmask,
            gateway,
            ip_source,
        })
    }
}

/// Parsed SDCP payload including security footer.
#[derive(Debug)]
pub struct ParsedSdcpPayload<'a> {
    pub header: SdcpHeader,
    pub tlv_payload: &'a [u8],
    pub sequence_number: u64,
    pub auth_tag: [u8; 32],
}

/// Parse a raw SDCP payload into header, TLV payload, and security footer.
pub fn parse_sdcp_payload(payload: &[u8]) -> Result<ParsedSdcpPayload<'_>, StatusCode> {
    let (payload_without_footer, footer) =
        split_payload_and_footer(payload).map_err(|_| StatusCode::ErrInvalidLen)?;

    if payload_without_footer.len() < SDCP_HEADER_SIZE as usize {
        return Err(StatusCode::ErrInvalidLen);
    }

    let header =
        SdcpHeader::read_from(payload_without_footer).map_err(|_| StatusCode::ErrFrameParsing)?;
    let tlv_payload = &payload_without_footer[SDCP_HEADER_SIZE as usize..];

    Ok(ParsedSdcpPayload {
        header,
        tlv_payload,
        sequence_number: footer.sequence_number,
        auth_tag: footer.auth_tag,
    })
}

/// Append a security footer to an SDCP payload buffer.
pub fn append_sdcp_footer(payload: &mut Vec<u8>, footer: &SecurityFooter) {
    footer.write_to(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VENDOR_ID: u16 = 0x1234;
    const TEST_DEVICE_ID: u16 = 0x5678;
    const TEST_SERIAL: u32 = 0xDEADBEEF;
    const TEST_IP: [u8; 4] = [192, 168, 1, 100];
    const TEST_NETMASK: [u8; 4] = [255, 255, 255, 0];
    const TEST_GATEWAY: [u8; 4] = [192, 168, 1, 1];

    #[test]
    fn test_discovered_device_creation() {
        let mac = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let device_info = DeviceInfo {
            vendor_id: TEST_VENDOR_ID,
            device_id: TEST_DEVICE_ID,
            serial_number: TEST_SERIAL,
        };

        let device = DiscoveredDevice::new(mac, device_info);

        assert_eq!(device.mac_address, mac);
        assert_eq!(device.vendor_id, TEST_VENDOR_ID);
        assert_eq!(device.device_id, TEST_DEVICE_ID);
        assert_eq!(device.serial_number, TEST_SERIAL);
    }

    #[test]
    fn test_sdcp_op_code_from_u8() {
        assert_eq!(SdcpOpCode::from(0x01), SdcpOpCode::DiscoverReq);
        assert_eq!(SdcpOpCode::from(0x02), SdcpOpCode::DiscoverRes);
        assert_eq!(SdcpOpCode::from(0x03), SdcpOpCode::SetIpReq);
        assert_eq!(SdcpOpCode::from(0x04), SdcpOpCode::SetIpRes);
        assert_eq!(SdcpOpCode::from(0x05), SdcpOpCode::GetIpReq);
        assert_eq!(SdcpOpCode::from(0x06), SdcpOpCode::GetIpRes);
        assert_eq!(SdcpOpCode::from(0x07), SdcpOpCode::ActivateDhcpReq);
        assert_eq!(SdcpOpCode::from(0x08), SdcpOpCode::ActivateDhcpRes);
        assert_eq!(SdcpOpCode::from(0x00), SdcpOpCode::UnknownOperation);
        assert_eq!(SdcpOpCode::from(0xFF), SdcpOpCode::UnknownOperation);
    }

    #[test]
    fn test_sdcp_header_new() {
        let header = SdcpHeader::new(SdcpOpCode::DiscoverReq, 0x1234);

        assert_eq!(header.version, SDCP_VERSION);
        assert_eq!(header.op_code, SdcpOpCode::DiscoverReq);
        let transaction_id = { header.transaction_id };
        assert_eq!(transaction_id, 0x1234);
        assert_eq!(header.flags, SDCP_FLAGS);
    }

    #[test]
    fn test_sdcp_header_write_read_roundtrip() {
        let original = SdcpHeader::new(SdcpOpCode::SetIpReq, 0x5678);
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();

        let read = SdcpHeader::read_from(&buf).unwrap();

        assert_eq!(read.version, original.version);
        assert_eq!(read.op_code, original.op_code);
        let (read_tid, orig_tid) = ({ read.transaction_id }, { original.transaction_id });
        assert_eq!(read_tid, orig_tid);
    }

    #[test]
    fn test_tlv_device_info() {
        let tlv = Tlv::device_info(TEST_VENDOR_ID, TEST_DEVICE_ID, TEST_SERIAL);

        assert_eq!(tlv.t_type, TLV_TYPE_DEVICE_INFO);
        let parsed = tlv.parse_device_info().unwrap();
        assert_eq!(parsed.vendor_id, TEST_VENDOR_ID);
        assert_eq!(parsed.device_id, TEST_DEVICE_ID);
        assert_eq!(parsed.serial_number, TEST_SERIAL);
    }

    #[test]
    fn test_tlv_ip_config() {
        let tlv = Tlv::ip_config(TEST_IP, TEST_NETMASK, TEST_GATEWAY);

        let parsed = tlv.parse_ip_config().unwrap();
        assert_eq!(parsed.ip, TEST_IP);
        assert_eq!(parsed.netmask, TEST_NETMASK);
        assert_eq!(parsed.gateway, TEST_GATEWAY);
    }

    #[test]
    fn test_tlv_ip_report() {
        let tlv = Tlv::ip_report(TEST_IP, TEST_NETMASK, TEST_GATEWAY, IpSource::Dhcp);

        let parsed = tlv.parse_ip_report().unwrap();
        assert_eq!(parsed.ip, TEST_IP);
        assert_eq!(parsed.netmask, TEST_NETMASK);
        assert_eq!(parsed.gateway, TEST_GATEWAY);
        assert_eq!(parsed.ip_source, IpSource::Dhcp);
    }

    #[test]
    fn test_tlv_status_report() {
        let tlv = Tlv::status_report(StatusCode::ErrIpConflict);

        assert_eq!(tlv.t_type, TLV_TYPE_STATUS_REPORT);
        assert_eq!(tlv.parse_status_report(), Some(StatusCode::ErrIpConflict));
    }

    #[test]
    fn test_tlv_write_read_roundtrip() {
        let original = Tlv::device_info(TEST_VENDOR_ID, TEST_DEVICE_ID, TEST_SERIAL);
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();

        let read = Tlv::read_from(&buf).unwrap();

        assert_eq!(read.t_type, original.t_type);
        assert_eq!(read.value, original.value);
    }

    #[test]
    fn test_tlv_parse_wrong_type_returns_none() {
        let ip_config_tlv = Tlv::ip_config(TEST_IP, TEST_NETMASK, TEST_GATEWAY);

        assert!(ip_config_tlv.parse_device_info().is_none());
        assert!(ip_config_tlv.parse_status_report().is_none());
        assert!(ip_config_tlv.parse_ip_report().is_none());
    }

    #[test]
    fn test_tlv_parse_wrong_length_returns_none() {
        let short_tlv = Tlv::new(TLV_TYPE_DEVICE_INFO, vec![0; 4]);
        assert!(short_tlv.parse_device_info().is_none());

        let short_ip_tlv = Tlv::new(TLV_TYPE_IP_CONFIG, vec![0; 8]);
        assert!(short_ip_tlv.parse_ip_config().is_none());

        let short_report_tlv = Tlv::new(TLV_TYPE_IP_REPORT, vec![0; 12]);
        assert!(short_report_tlv.parse_ip_report().is_none());

        let long_status_tlv = Tlv::new(TLV_TYPE_STATUS_REPORT, vec![0; 2]);
        assert!(long_status_tlv.parse_status_report().is_none());
    }

    #[test]
    fn test_parse_sdcp_payload_extracts_footer() {
        let mut payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::DiscoverReq, 0x1234);
        header.write_to(&mut payload).unwrap();
        let tlv = Tlv::device_info(TEST_VENDOR_ID, TEST_DEVICE_ID, TEST_SERIAL);
        tlv.write_to(&mut payload).unwrap();

        let footer = SecurityFooter {
            sequence_number: 11,
            auth_tag: [0xAA; 32],
        };
        append_sdcp_footer(&mut payload, &footer);

        let parsed = parse_sdcp_payload(&payload).expect("payload should parse");
        assert_eq!(parsed.header.op_code, SdcpOpCode::DiscoverReq);
        let parsed_tlv = Tlv::read_from(parsed.tlv_payload).unwrap();
        assert_eq!(
            parsed_tlv.parse_device_info().unwrap().vendor_id,
            TEST_VENDOR_ID
        );
        assert_eq!(parsed.sequence_number, 11);
        assert_eq!(parsed.auth_tag, [0xAA; 32]);
    }

    #[test]
    fn test_parse_sdcp_payload_rejects_short_input() {
        let short = vec![0u8; SDCP_HEADER_SIZE as usize + 10];
        assert!(matches!(
            parse_sdcp_payload(&short),
            Err(StatusCode::ErrInvalidLen)
        ));
    }
}
