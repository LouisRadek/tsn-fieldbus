//! Shared Mock Implementations for Testing
//!
//! This module provides reusable mock implementations of hardware abstraction
//! traits for use in both unit tests and integration tests across the workspace.
//!
//! # Available Mocks
//!
//! - [`MockDeviceInfo`]: Mock implementation of `DeviceInfoAccess`
//! - [`MockNetworkInterface`]: Mock implementation of `NetworkInterfaceAccess`
//! - [`create_mock_interface`]: Factory for creating mock `pnet::NetworkInterface`
//! - [`MockDataLinkSender`]: Mock implementation of the `pnet::DataLinkSender`
//! - [`MockDataLinkReceiver`]: Mock implementation of the `pnet::DataLinkReceiver`
//!
//! # Feature Gate
//!
//! This module is only available when the `test-utils` feature is enabled
//! or during test compilation.

use crate::hardware_abstraction::{DeviceInfoAccess, NetworkInterfaceAccess};
use crate::slave_api::{DeviceInfo, IpSource, StatusCode};
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::util::MacAddr;
use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;

pub const TEST_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

pub struct MockDeviceInfo {
    info: Mutex<DeviceInfo>,
}

impl MockDeviceInfo {
    /// Creates a new `MockDeviceInfo` with default values.
    ///
    /// Default configuration:
    /// - IP: 192.168.1.100
    /// - Netmask: 255.255.255.0
    /// - Gateway: 192.168.1.1
    /// - Vendor ID: 0x1234
    /// - Device ID: 0x5678
    /// - Serial Number: 0xDEADBEEF
    pub fn new(mac: MacAddr) -> Self {
        Self {
            info: Mutex::new(DeviceInfo {
                mac_address: mac.octets().to_vec(),
                ip_address: vec![192, 168, 1, 100],
                ip_source: IpSource::Manuell.into(),
                netmask: vec![255, 255, 255, 0],
                gateway: vec![192, 168, 1, 1],
                vendor_id: 0x1234,
                device_id: 0x5678,
                serial_number: 0xDEADBEEF,
                firmware_version: 1,
                capabilities: 0,
            }),
        }
    }

    pub fn with_ip(mac: MacAddr, ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> Self {
        let mock = Self::new(mac);
        {
            let mut info = mock.info.lock().unwrap();
            info.ip_address = ip.to_vec();
            info.netmask = netmask.to_vec();
            info.gateway = gateway.to_vec();
        }
        mock
    }
}

impl DeviceInfoAccess for MockDeviceInfo {
    fn read_device_info(&self) -> Result<DeviceInfo, StatusCode> {
        Ok(self.info.lock().unwrap().clone())
    }

    fn write_device_info(&self, info: DeviceInfo) -> Result<(), StatusCode> {
        *self.info.lock().unwrap() = info;
        Ok(())
    }
}

pub struct MockNetworkInterface {
    #[allow(clippy::type_complexity)]
    applied_configs: Mutex<Vec<([u8; 4], [u8; 4], [u8; 4])>>,
    should_fail: bool,
}

impl MockNetworkInterface {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            applied_configs: Mutex::new(Vec::new()),
            should_fail: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            applied_configs: Mutex::new(Vec::new()),
            should_fail: true,
        }
    }

    pub fn get_applied_configs(&self) -> Vec<([u8; 4], [u8; 4], [u8; 4])> {
        self.applied_configs.lock().unwrap().clone()
    }

    pub fn was_called(&self) -> bool {
        !self.applied_configs.lock().unwrap().is_empty()
    }
}

impl NetworkInterfaceAccess for MockNetworkInterface {
    fn apply_ip_config(
        &self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
    ) -> Result<(), StatusCode> {
        if self.should_fail {
            Err(StatusCode::ErrOsFailure)
        } else {
            self.applied_configs
                .lock()
                .unwrap()
                .push((ip, netmask, gateway));
            Ok(())
        }
    }
}

pub fn create_mock_interface(name: &str, mac: MacAddr) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        description: format!("Mock interface {name}"),
        index: 0,
        mac: Some(mac),
        ips: vec![],
        flags: 0,
    }
}

pub struct MockDataLinkSender {
    sent_packets: Mutex<Vec<Vec<u8>>>,
}

impl MockDataLinkSender {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            sent_packets: Mutex::new(Vec::new()),
        }
    }

    pub fn get_sent_packets(&self) -> Vec<Vec<u8>> {
        self.sent_packets.lock().unwrap().clone()
    }
}

impl datalink::DataLinkSender for MockDataLinkSender {
    fn send_to(
        &mut self,
        packet: &[u8],
        _dst: Option<pnet::datalink::NetworkInterface>,
    ) -> Option<Result<(), std::io::Error>> {
        self.sent_packets.lock().unwrap().push(packet.to_vec());
        Some(Ok(()))
    }

    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<Result<(), std::io::Error>> {
        Some(Ok(()))
    }
}

pub struct MockDataLinkReceiver {
    frames: Mutex<VecDeque<Vec<u8>>>,
    current_frame: Vec<u8>,
}

impl MockDataLinkReceiver {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            frames: Mutex::new(VecDeque::new()),
            current_frame: Vec::new(),
        }
    }

    pub fn add_response_frame(&self, frame: Vec<u8>) {
        self.frames.lock().unwrap().push_back(frame);
    }
}

impl DataLinkReceiver for MockDataLinkReceiver {
    fn next(&mut self) -> Result<&[u8], io::Error> {
        if let Some(frame) = self.frames.lock().unwrap().pop_front() {
            self.current_frame = frame;
            Ok(&self.current_frame)
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "No frames available",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::DataLinkSender;

    #[test]
    fn test_mock_device_info_default_values() {
        let mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let mock = MockDeviceInfo::new(mac);
        let info = mock.read_device_info().unwrap();

        assert_eq!(info.mac_address, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(info.ip_address, vec![192, 168, 1, 100]);
        assert_eq!(info.vendor_id, 0x1234);
        assert_eq!(info.device_id, 0x5678);
        assert_eq!(info.serial_number, 0xDEADBEEF);
    }

    #[test]
    fn test_mock_device_info_with_custom_ip() {
        let mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let mock = MockDeviceInfo::with_ip(mac, [10, 0, 0, 50], [255, 255, 0, 0], [10, 0, 0, 1]);
        let info = mock.read_device_info().unwrap();

        assert_eq!(info.ip_address, vec![10, 0, 0, 50]);
        assert_eq!(info.netmask, vec![255, 255, 0, 0]);
        assert_eq!(info.gateway, vec![10, 0, 0, 1]);
    }

    #[test]
    fn test_mock_device_info_write_read() {
        let mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let mock = MockDeviceInfo::new(mac);

        let mut info = mock.read_device_info().unwrap();
        info.ip_address = vec![172, 16, 0, 1];
        mock.write_device_info(info).unwrap();

        let updated = mock.read_device_info().unwrap();
        assert_eq!(updated.ip_address, vec![172, 16, 0, 1]);
    }

    #[test]
    fn test_mock_network_interface_success() {
        let mock = MockNetworkInterface::new();

        let result = mock.apply_ip_config([10, 0, 0, 1], [255, 255, 255, 0], [10, 0, 0, 254]);
        assert!(result.is_ok());
        assert!(mock.was_called());

        let configs = mock.get_applied_configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(
            configs[0],
            ([10, 0, 0, 1], [255, 255, 255, 0], [10, 0, 0, 254])
        );
    }

    #[test]
    fn test_mock_network_interface_failure() {
        let mock = MockNetworkInterface::failing();

        let result = mock.apply_ip_config([10, 0, 0, 1], [255, 255, 255, 0], [10, 0, 0, 254]);
        assert!(result.is_err());
        assert!(!mock.was_called());
    }

    #[test]
    fn test_create_mock_interface() {
        let mac = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let interface = create_mock_interface("test0", mac);

        assert_eq!(interface.name, "test0");
        assert_eq!(interface.mac, Some(mac));
    }

    #[test]
    fn test_mock_datalink_sender_captures_packets() {
        let mut sender = MockDataLinkSender::new();

        let packet1 = vec![0x01, 0x02, 0x03, 0x04];
        let packet2 = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let result1 = sender.send_to(&packet1, None);
        let result2 = sender.send_to(&packet2, None);

        assert!(result1.is_some());
        assert!(result1.unwrap().is_ok());
        assert!(result2.is_some());
        assert!(result2.unwrap().is_ok());

        let sent = sender.get_sent_packets();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], packet1);
        assert_eq!(sent[1], packet2);
    }

    #[test]
    fn test_mock_datalink_sender_empty_initially() {
        let sender = MockDataLinkSender::new();
        let sent = sender.get_sent_packets();
        assert!(sent.is_empty());
    }

    #[test]
    fn test_mock_datalink_sender_build_and_send() {
        let mut sender = MockDataLinkSender::new();

        let result = sender.build_and_send(1, 64, &mut |_buffer| {});

        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_mock_datalink_receiver_returns_frames_in_order() {
        let mut receiver = MockDataLinkReceiver::new();

        let frame1 = vec![0x01, 0x02, 0x03];
        let frame2 = vec![0x04, 0x05, 0x06];
        let frame3 = vec![0x07, 0x08, 0x09];

        receiver.add_response_frame(frame1.clone());
        receiver.add_response_frame(frame2.clone());
        receiver.add_response_frame(frame3.clone());

        let received1 = receiver.next().unwrap();
        assert_eq!(received1, &frame1[..]);

        let received2 = receiver.next().unwrap();
        assert_eq!(received2, &frame2[..]);

        let received3 = receiver.next().unwrap();
        assert_eq!(received3, &frame3[..]);
    }

    #[test]
    fn test_mock_datalink_receiver_empty_returns_would_block() {
        let mut receiver = MockDataLinkReceiver::new();

        let result = receiver.next();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_mock_datalink_receiver_exhausted_returns_would_block() {
        let mut receiver = MockDataLinkReceiver::new();

        receiver.add_response_frame(vec![0x01, 0x02]);

        let _ = receiver.next().unwrap();

        let result = receiver.next();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_mock_datalink_receiver_large_frame() {
        let mut receiver = MockDataLinkReceiver::new();

        let large_frame: Vec<u8> = (0..1500).map(|i| (i % 256) as u8).collect();
        receiver.add_response_frame(large_frame.clone());

        let received = receiver.next().unwrap();
        assert_eq!(received.len(), 1500);
        assert_eq!(received, &large_frame[..]);
    }

    #[test]
    fn test_mock_datalink_receiver_can_add_frames_after_consumption() {
        let mut receiver = MockDataLinkReceiver::new();

        receiver.add_response_frame(vec![0x01]);
        let _ = receiver.next().unwrap();

        receiver.add_response_frame(vec![0x02]);
        let received = receiver.next().unwrap();
        assert_eq!(received, &[0x02]);
    }
}
