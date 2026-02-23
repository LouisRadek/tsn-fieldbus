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
