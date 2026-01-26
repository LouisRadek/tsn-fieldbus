#![allow(dead_code)]
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read};

use crate::status_codes::StatusCode;

pub const ETHERTYPE_SDCP: u16 = 0x88B5;
pub const SDCP_VERSION: u8 = 0x01;
pub const SDCP_FLAGS: u8 = 0x00;
pub const TLV_TYPE_DEVICE_INFO: u8 = 0x01;
pub const TLV_TYPE_IP_CONFIG: u8 = 0x02;
pub const TLV_TYPE_STATUS_REPORT: u8 = 0x03;
pub const TLV_TYPE_IP_REPORT: u8 = 0x04;

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

#[repr(C, packed)]
#[derive(Debug)]
pub struct SdcpHeader {
    version: u8,
    op_code: SdcpOpCode,
    transaction_id: u16,
    flags: u8,
}

impl SdcpHeader {
    pub fn new(op_code: SdcpOpCode, transaction_id: u16) -> Self {
        Self {
            version: SDCP_VERSION,
            op_code,
            transaction_id,
            flags: SDCP_FLAGS,
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.write_u8(self.version)?;
        buf.write_u8(self.op_code as u8)?;
        buf.write_u16::<BigEndian>(self.transaction_id)?;
        buf.write_u8(self.flags)?;
        Ok(())
    }

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

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_op_code(&self) -> SdcpOpCode {
        self.op_code
    }

    pub fn get_transaction_id(&self) -> u16 {
        self.transaction_id
    }

    pub fn get_flags(&self) -> u8 {
        self.flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpSource {
    Sdcp = 0x01,
    Manuell = 0x02,
    Dhcp = 0x03,
    Unspecified = 0x04,
}

impl From<u8> for IpSource {
    fn from(val: u8) -> Self {
        match val {
            0x01 => IpSource::Sdcp,
            0x02 => IpSource::Manuell,
            0x03 => IpSource::Dhcp,
            _ => IpSource::Unspecified,
        }
    }
}

#[derive(Debug)]
pub struct DeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub serial_number: u32,
}

#[derive(Debug)]
pub struct IpConfig {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
}

#[derive(Debug)]
pub struct StatusReport {
    pub status_code: u8,
}

#[derive(Debug)]
pub struct IpReport {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub ip_source: IpSource,
}

#[derive(Debug)]
pub struct Tlv {
    t_type: u8,
    length: u8,
    value: Vec<u8>,
}

impl Tlv {
    pub fn new(t_type: u8, value: Vec<u8>) -> Self {
        Self {
            t_type,
            length: value.len() as u8,
            value,
        }
    }

    pub fn get_type(&self) -> u8 {
        self.t_type
    }

    pub fn device_info(vendor_id: u16, device_id: u16, serial_number: u32) -> Self {
        let mut value = Vec::with_capacity(8);
        value.extend_from_slice(&vendor_id.to_be_bytes());
        value.extend_from_slice(&device_id.to_be_bytes());
        value.extend_from_slice(&serial_number.to_be_bytes());
        Tlv::new(TLV_TYPE_DEVICE_INFO, value)
    }

    pub fn ip_config(ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> Self {
        let mut value = Vec::with_capacity(12);
        value.extend_from_slice(&ip);
        value.extend_from_slice(&netmask);
        value.extend_from_slice(&gateway);
        Tlv::new(TLV_TYPE_IP_CONFIG, value)
    }

    pub fn status_report(status_code: u8) -> Self {
        Tlv::new(TLV_TYPE_STATUS_REPORT, vec![status_code])
    }

    pub fn ip_report(ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4], ip_source: IpSource) -> Self {
        let mut value = Vec::with_capacity(13);
        value.extend_from_slice(&ip);
        value.extend_from_slice(&netmask);
        value.extend_from_slice(&gateway);
        value.push(ip_source as u8);
        Tlv::new(TLV_TYPE_IP_REPORT, value)
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        buf.write_u8(self.t_type)?;
        buf.write_u8(self.length)?;
        buf.extend_from_slice(&self.value);
        Ok(())
    }

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

    pub fn parse_status_report(&self) -> Option<StatusCode> {
        if self.t_type != TLV_TYPE_STATUS_REPORT || self.value.len() != 1 {
            return None;
        }
        let status_code = self.value[0];
        Some(StatusCode::from(status_code))
    }

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
        let ip_source = IpSource::from(self.value[12]);
        Some(IpReport {
            ip,
            netmask,
            gateway,
            ip_source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdcp_op_code_from_u8() {
        assert_eq!(SdcpOpCode::from(0x01), SdcpOpCode::DiscoverReq);
        assert_eq!(SdcpOpCode::from(0x02), SdcpOpCode::DiscoverRes);
        assert_eq!(SdcpOpCode::from(0xFF), SdcpOpCode::UnknownOperation);
    }

    #[test]
    fn test_sdcp_header_new() {
        let header = SdcpHeader::new(SdcpOpCode::DiscoverReq, 0x1234);
        assert_eq!(header.get_version(), SDCP_VERSION);
        assert_eq!(header.get_op_code(), SdcpOpCode::DiscoverReq);
        assert_eq!(header.get_transaction_id(), 0x1234);
        assert_eq!(header.get_flags(), SDCP_FLAGS);
    }

    #[test]
    fn test_sdcp_header_write_read() {
        let original = SdcpHeader::new(SdcpOpCode::SetIpReq, 0x5678);
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();
        let read = SdcpHeader::read_from(&buf).unwrap();
        assert_eq!(read.get_version(), original.get_version());
        assert_eq!(read.get_op_code(), original.get_op_code());
        assert_eq!(read.get_transaction_id(), original.get_transaction_id());
    }

    #[test]
    fn test_ip_source_from_u8() {
        assert_eq!(IpSource::from(0x01), IpSource::Sdcp);
        assert_eq!(IpSource::from(0x02), IpSource::Manuell);
        assert_eq!(IpSource::from(0x03), IpSource::Dhcp);
        assert_eq!(IpSource::from(0xFF), IpSource::Unspecified);
    }

    #[test]
    fn test_tlv_device_info() {
        let tlv = Tlv::device_info(0x1234, 0x5678, 0xDEADBEEF);
        assert_eq!(tlv.get_type(), TLV_TYPE_DEVICE_INFO);
        let device_info_parsed = tlv.parse_device_info().unwrap();
        assert_eq!(device_info_parsed.vendor_id, 0x1234);
        assert_eq!(device_info_parsed.device_id, 0x5678);
        assert_eq!(device_info_parsed.serial_number, 0xDEADBEEF);
    }

    #[test]
    fn test_tlv_ip_config() {
        let ip = [192, 168, 1, 100];
        let netmask = [255, 255, 255, 0];
        let gateway = [192, 168, 1, 1];
        let tlv = Tlv::ip_config(ip, netmask, gateway);
        let ip_config_parsed = tlv.parse_ip_config().unwrap();
        assert_eq!(ip_config_parsed.ip, ip);
        assert_eq!(ip_config_parsed.netmask, netmask);
        assert_eq!(ip_config_parsed.gateway, gateway);
    }

    #[test]
    fn test_tlv_ip_report() {
        let ip = [10, 0, 0, 5];
        let netmask = [255, 255, 255, 0];
        let gateway = [10, 0, 0, 1];
        let tlv = Tlv::ip_report(ip, netmask, gateway, IpSource::Dhcp);
        let ip_report_parsed = tlv.parse_ip_report().unwrap();
        assert_eq!(ip_report_parsed.ip, ip);
        assert_eq!(ip_report_parsed.netmask, netmask);
        assert_eq!(ip_report_parsed.gateway, gateway);
        assert_eq!(ip_report_parsed.ip_source, IpSource::Dhcp);
    }

    #[test]
    fn test_tlv_write_read() {
        let original = Tlv::status_report(0x42);
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();
        let read = Tlv::read_from(&buf).unwrap();
        assert_eq!(read.get_type(), original.get_type());
        assert_eq!(read.value, original.value);
    }
}
