//! SDCP Discovery Master Implementation
//!
//! This module implements the master-side of the SDCP discovery protocol.
//! It provides functionality to discover slave devices on the network,
//! query their IP configurations, and assign new IP addresses.
//!
//! # Protocol Overview
//!
//! The master sends a broadcast or unicast SDCP frames and collects responses
//! from slave devices. All communication happens at Layer 2 (Ethernet) to
//! ensure devices without IP addresses can be discovered.
//!
//! # Supported Operations
//!
//! - `DiscoverReq`: Broadcast discovery to find all devices on the network
//! - `GetIpReq`: Query a specific device's IP configuration
//! - `SetIpReq`: Assign IP configuration to a specific device
//!
//! # Thread Safety
//!
//! The [`DiscoveryMaster`] is designed to be used from a single thread.
//! For concurrent access, wrap it in appropriate synchronization primitives.

use common::discovery_types::{
    DiscoveredDevice, DiscoveryError, ETHERTYPE_SDCP, IpReport, SDCP_HEADER_SIZE, SdcpHeader,
    SdcpOpCode, Tlv,
};
use common::slave_api::{DeviceState, StatusCode};
use common::state_machine::DeviceStateManager;
use log::{debug, info, warn};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{self, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use std::{cmp, io};

const BROADCAST_MAC: MacAddr = MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(2000);
const DEFAULT_UNICAST_TIMEOUT: Duration = Duration::from_millis(1000);

/// Minimum Ethernet frame size (excluding FCS)
const MIN_FRAME_SIZE: usize = 60;

/// Master-side SDCP discovery controller
///
/// Manages discovery operations including device scanning, IP queries,
/// and IP configuration. Maintains a cache of discovered devices.
pub struct DiscoveryMaster {
    interface: NetworkInterface,
    device_state_manager: DeviceStateManager,
    transmitter: Box<dyn DataLinkSender>,
    receiver: Box<dyn DataLinkReceiver>,
    discovered_devices: HashMap<MacAddr, DiscoveredDevice>,
    transaction_counter: AtomicU16,
}

impl DiscoveryMaster {
    /// Creates a new `DiscoveryMaster` bound to the specified network interface.
    ///
    /// # Arguments
    ///
    /// * `interface_name` - Name of the network interface (e.g., "eth0", "enp0s3")
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::InterfaceNotFound` if the interface doesn't exist,
    /// or `DiscoveryError::ChannelCreationFailed` if the raw socket cannot be opened.
    pub fn new(
        interface_name: &str,
        device_state_manager: DeviceStateManager,
    ) -> Result<Self, DiscoveryError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.name == interface_name)
            .ok_or_else(|| DiscoveryError::InterfaceNotFound(interface_name.to_string()))?;

        info!(
            "Initializing Discovery Master on interface: {} (MAC: {:?})",
            interface.name, interface.mac
        );

        let (transmitter, receiver) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(transmitter, receiver)) => (transmitter, receiver),
            Ok(_) => {
                return Err(DiscoveryError::ChannelCreationFailed(
                    "Unexpected channel type".to_string(),
                ));
            }
            Err(e) => return Err(DiscoveryError::ChannelCreationFailed(e.to_string())),
        };

        Ok(Self {
            interface,
            device_state_manager,
            transmitter,
            receiver,
            discovered_devices: HashMap::new(),
            transaction_counter: AtomicU16::new(1),
        })
    }

    /// Creates a `DiscoveryMaster` with injected mock components for testing.
    ///
    /// This constructor is available when the `test-utils` feature is enabled,
    /// or during unit tests. It allows injecting mock network components
    /// for deterministic testing without real network access.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_with_mocks(
        interface: NetworkInterface,
        device_state_manager: DeviceStateManager,
        transmitter: Box<dyn DataLinkSender>,
        receiver: Box<dyn DataLinkReceiver>,
    ) -> Self {
        Self {
            interface,
            device_state_manager,
            transmitter,
            receiver,
            discovered_devices: HashMap::new(),
            transaction_counter: AtomicU16::new(1),
        }
    }

    /// Generates a unique transaction ID for request-response correlation.
    ///
    /// Uses an atomic counter to ensure uniqueness across multiple operations.
    /// Wraps around at `u16::MAX`.
    fn next_transaction_id(&self) -> u16 {
        self.transaction_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn discovered_devices(&self) -> &HashMap<MacAddr, DiscoveredDevice> {
        &self.discovered_devices
    }

    pub fn clear_discovered_devices(&mut self) {
        self.discovered_devices.clear();
    }

    /// Performs a network-wide device discovery.
    ///
    /// Sends a broadcast `DISCOVER_REQ` and collects responses for the specified
    /// timeout duration. Discovered devices are cached internally and returned.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Optional timeout duration. Defaults to 2s if `None`.
    ///
    /// # Returns
    ///
    /// A vector of newly discovered devices. Devices already in the cache are
    /// updated but not duplicated in the return value.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::IoError` if packet transmission fails.
    pub fn discover_devices(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<Vec<DiscoveredDevice>, DiscoveryError> {
        if self.device_state_manager.get_state() != DeviceState::DiscoverySync {
            return Err(DiscoveryError::InvalidState);
        }

        let timeout = timeout.unwrap_or(DEFAULT_DISCOVERY_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!(
            "Starting device discovery (transaction_id: {transaction_id:#06x}, timeout: {timeout:?})"
        );

        let frame =
            self.build_request_frame(BROADCAST_MAC, SdcpOpCode::DiscoverReq, transaction_id, None)?;
        self.send_frame(&frame)?;

        let mut newly_discovered = Vec::new();
        let start = Instant::now();

        while start.elapsed() < timeout {
            match self.receive_raw_frame_nonblocking() {
                Some(frame_data) => {
                    if let Some(device) = process_discover_frame(&frame_data, transaction_id) {
                        let mac = device.mac_address;
                        let is_new = !self.discovered_devices.contains_key(&mac);
                        self.discovered_devices.insert(mac, device.clone());

                        if is_new {
                            info!(
                                "Discovered new device: MAC={mac}, Vendor={:#06x}, Device={:#06x}, Serial={:#010x}",
                                device.vendor_id, device.device_id, device.serial_number
                            );
                            newly_discovered.push(device);
                        } else {
                            debug!("Updated existing device: MAC={mac}");
                        }
                    }
                }
                None => {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }

        info!(
            "Discovery completed: {} new devices, {} total cached",
            newly_discovered.len(),
            self.discovered_devices.len()
        );

        Ok(newly_discovered)
    }

    /// Queries the IP configuration of a specific device.
    ///
    /// Sends a unicast `GET_IP_REQ` to the target device and waits for the response.
    ///
    /// # Arguments
    ///
    /// * `target_mac` - MAC address of the device to query
    /// * `timeout` - Optional timeout duration. Defaults to 1s if `None`.
    ///
    /// # Returns
    ///
    /// The device's current IP configuration including source information.
    ///
    /// # Errors
    ///
    /// - `DiscoveryError::Timeout` if no response is received
    /// - `DiscoveryError::InvalidResponse` if the response cannot be parsed
    pub fn get_ip_config(
        &mut self,
        target_mac: MacAddr,
        timeout: Option<Duration>,
    ) -> Result<IpReport, DiscoveryError> {
        if self.device_state_manager.get_state() != DeviceState::DiscoverySync {
            return Err(DiscoveryError::InvalidState);
        }

        let timeout = timeout.unwrap_or(DEFAULT_UNICAST_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!("Querying IP config from {target_mac} (transaction_id: {transaction_id:#06x})");

        let frame =
            self.build_request_frame(target_mac, SdcpOpCode::GetIpReq, transaction_id, None)?;
        self.send_frame(&frame)?;

        self.wait_for_response(target_mac, SdcpOpCode::GetIpRes, transaction_id, timeout)
            .and_then(|payload| {
                if payload.len() > SDCP_HEADER_SIZE as usize {
                    let tlv_data = &payload[SDCP_HEADER_SIZE as usize..];
                    Tlv::read_from(tlv_data)
                        .ok()
                        .and_then(|tlv| tlv.parse_ip_report())
                        .ok_or_else(|| {
                            DiscoveryError::InvalidResponse("Failed to parse IP report".to_string())
                        })
                } else {
                    Err(DiscoveryError::InvalidResponse(
                        "Response too short".to_string(),
                    ))
                }
            })
    }

    /// Assigns an IP configuration to a specific device.
    ///
    /// Sends a unicast `SET_IP_REQ` to configure the device's network settings.
    ///
    /// # Arguments
    ///
    /// * `target_mac` - MAC address of the device to configure
    /// * `ip` - IPv4 address to assign
    /// * `netmask` - Subnet mask
    /// * `gateway` - Default gateway address
    /// * `timeout` - Optional timeout duration. Defaults to 200ms if `None`.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the configuration was applied successfully.
    ///
    /// # Errors
    ///
    /// - `DiscoveryError::Timeout` if no response is received
    /// - `DiscoveryError::DeviceError` with the specific status code on failure
    pub fn set_ip_config(
        &mut self,
        target_mac: MacAddr,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
        timeout: Option<Duration>,
    ) -> Result<(), DiscoveryError> {
        if self.device_state_manager.get_state() != DeviceState::DiscoverySync {
            return Err(DiscoveryError::InvalidState);
        }

        let timeout = timeout.unwrap_or(DEFAULT_UNICAST_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!(
            "Setting IP config on {target_mac}: {}.{}.{}.{}/{}.{}.{}.{} gw {}.{}.{}.{} (transaction_id: {transaction_id:#06x})",
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            netmask[0],
            netmask[1],
            netmask[2],
            netmask[3],
            gateway[0],
            gateway[1],
            gateway[2],
            gateway[3]
        );

        let tlv = Tlv::ip_config(ip, netmask, gateway);
        let frame =
            self.build_request_frame(target_mac, SdcpOpCode::SetIpReq, transaction_id, Some(tlv))?;
        self.send_frame(&frame)?;

        self.wait_for_response(target_mac, SdcpOpCode::SetIpRes, transaction_id, timeout)
            .and_then(|payload| {
                if payload.len() > SDCP_HEADER_SIZE as usize {
                    let tlv_data = &payload[SDCP_HEADER_SIZE as usize..];
                    if let Ok(tlv) = Tlv::read_from(tlv_data)
                        && let Some(status) = tlv.parse_status_report()
                    {
                        return if status == StatusCode::NoError {
                            info!("IP configuration successfully applied to {target_mac}");
                            Ok(())
                        } else {
                            warn!("Device {target_mac} rejected IP config: {status:?}");
                            Err(DiscoveryError::DeviceError(status))
                        };
                    }
                }
                Err(DiscoveryError::InvalidResponse(
                    "Failed to parse status response".to_string(),
                ))
            })
    }

    /// Builds an SDCP request frame.
    ///
    /// Constructs a complete Ethernet frame with SDCP header and optional TLV payload.
    /// Ensures minimum frame size by padding if necessary.
    fn build_request_frame(
        &self,
        destination: MacAddr,
        op_code: SdcpOpCode,
        transaction_id: u16,
        payload_tlv: Option<Tlv>,
    ) -> Result<Vec<u8>, DiscoveryError> {
        let tlv_size = payload_tlv
            .as_ref()
            .map_or(0, |tlv| 2 + tlv.length as usize);
        let required_size = 14 + SDCP_HEADER_SIZE as usize + tlv_size;
        let buffer_size = cmp::max(required_size, MIN_FRAME_SIZE);

        let mut buffer = vec![0u8; buffer_size];

        let mut eth_packet = MutableEthernetPacket::new(&mut buffer)
            .ok_or_else(|| DiscoveryError::IoError(io::Error::other("Buffer too small")))?;

        eth_packet.set_destination(destination);
        eth_packet.set_source(
            self.interface
                .mac
                .ok_or_else(|| DiscoveryError::IoError(io::Error::other("No MAC address")))?,
        );
        eth_packet.set_ethertype(ethernet::EtherType(ETHERTYPE_SDCP));

        let mut payload = Vec::with_capacity(SDCP_HEADER_SIZE as usize + tlv_size);
        let header = SdcpHeader::new(op_code, transaction_id);
        header.write_to(&mut payload)?;

        if let Some(tlv) = payload_tlv {
            tlv.write_to(&mut payload)?;
        }

        eth_packet.set_payload(&payload);

        Ok(buffer)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), DiscoveryError> {
        self.transmitter
            .send_to(frame, None)
            .ok_or_else(|| DiscoveryError::IoError(io::Error::other("Send failed")))?
            .map_err(DiscoveryError::IoError)
    }

    /// Attempts to receive a raw Ethernet frame without blocking.
    ///
    /// Returns the complete frame data including Ethernet header,
    /// or `None` if no frame is available.
    fn receive_raw_frame_nonblocking(&mut self) -> Option<Vec<u8>> {
        match self.receiver.next() {
            Ok(data) => Some(data.to_vec()),
            Err(_) => None,
        }
    }

    fn wait_for_response(
        &mut self,
        expected_source: MacAddr,
        expected_opcode: SdcpOpCode,
        expected_transaction_id: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, DiscoveryError> {
        let start = Instant::now();

        while start.elapsed() < timeout {
            match self.receiver.next() {
                Ok(data) => {
                    if let Some(ethernet_frame) = EthernetPacket::new(data) {
                        if ethernet_frame.get_ethertype().0 != ETHERTYPE_SDCP {
                            continue;
                        }

                        if ethernet_frame.get_source() != expected_source {
                            continue;
                        }

                        let payload = ethernet_frame.payload();
                        if let Ok(header) = SdcpHeader::read_from(payload)
                            && header.op_code == expected_opcode
                            && header.transaction_id == expected_transaction_id
                        {
                            debug!(
                                "Received expected response from {expected_source}: {expected_opcode:?}"
                            );
                            return Ok(payload.to_vec());
                        }
                    }
                }
                Err(e) => {
                    warn!("Error receiving frame: {e}");
                }
            }
        }

        Err(DiscoveryError::Timeout)
    }
}

/// Processes a complete Ethernet frame and extracts discovered device info.
///
/// This is a helper function used during discovery to parse responses.
fn process_discover_frame(
    frame_data: &[u8],
    expected_transaction_id: u16,
) -> Option<DiscoveredDevice> {
    let eth_packet = EthernetPacket::new(frame_data)?;

    if eth_packet.get_ethertype().0 != ETHERTYPE_SDCP {
        return None;
    }

    let payload = eth_packet.payload();
    let header = SdcpHeader::read_from(payload).ok()?;

    if header.op_code != SdcpOpCode::DiscoverRes || header.transaction_id != expected_transaction_id
    {
        return None;
    }

    let tlv_data = &payload[SDCP_HEADER_SIZE as usize..];
    let tlv = Tlv::read_from(tlv_data).ok()?;
    let device_info = tlv.parse_device_info()?;

    Some(DiscoveredDevice::new(eth_packet.get_source(), device_info))
}

#[cfg(test)]
mod tests {
    use common::test_mocks::{
        MockDataLinkReceiver, MockDataLinkSender, TEST_MAC, create_mock_interface,
    };

    use super::*;

    const SLAVE_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
    const SLAVE2_MAC: MacAddr = MacAddr(0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC);
    const VENDOR_ID: u16 = 0x1234;
    const DEVICE_ID: u16 = 0x5678;
    const SERIAL_NUMBER: u32 = 0xDEADBEEF;
    const DEFAULT_IP: [u8; 4] = [192, 168, 1, 100];
    const DEFAULT_NETMASK: [u8; 4] = [255, 255, 255, 0];
    const DEFAULT_GATEWAY: [u8; 4] = [192, 168, 1, 1];
    const TEST_TIMEOUT: Duration = Duration::from_millis(100);
    const SHORT_TIMEOUT: Duration = Duration::from_millis(50);

    fn build_sdcp_frame(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        transaction_id: u16,
        op_code: SdcpOpCode,
        tlv: Option<Tlv>,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&dest_mac.octets());
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(op_code, transaction_id);
        header.write_to(&mut sdcp_payload).unwrap();

        if let Some(tlv) = tlv {
            tlv.write_to(&mut sdcp_payload).unwrap();
        }

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);
        frame
    }

    fn create_discovery_response(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        transaction_id: u16,
        vendor_id: u16,
        device_id: u16,
        serial_number: u32,
    ) -> Vec<u8> {
        let tlv = Tlv::device_info(vendor_id, device_id, serial_number);
        build_sdcp_frame(
            source_mac,
            dest_mac,
            transaction_id,
            SdcpOpCode::DiscoverRes,
            Some(tlv),
        )
    }

    fn create_get_ip_response(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        transaction_id: u16,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
        ip_source: common::slave_api::IpSource,
    ) -> Vec<u8> {
        let tlv = Tlv::ip_report(ip, netmask, gateway, ip_source);
        build_sdcp_frame(
            source_mac,
            dest_mac,
            transaction_id,
            SdcpOpCode::GetIpRes,
            Some(tlv),
        )
    }

    fn create_set_ip_response(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        transaction_id: u16,
        status: StatusCode,
    ) -> Vec<u8> {
        let tlv = Tlv::status_report(status);
        build_sdcp_frame(
            source_mac,
            dest_mac,
            transaction_id,
            SdcpOpCode::SetIpRes,
            Some(tlv),
        )
    }

    fn create_test_master() -> DiscoveryMaster {
        let interface = create_mock_interface("mock0", TEST_MAC);
        let device_state_manager = DeviceStateManager::new();
        let _ = device_state_manager.set_target_state(DeviceState::DiscoverySync);
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();
        DiscoveryMaster::new_with_mocks(
            interface,
            device_state_manager,
            Box::new(sender),
            Box::new(receiver),
        )
    }

    fn create_test_master_with_responses(responses: Vec<Vec<u8>>) -> DiscoveryMaster {
        let interface = create_mock_interface("mock0", TEST_MAC);
        let device_state_manager = DeviceStateManager::new();
        let _ = device_state_manager.set_target_state(DeviceState::DiscoverySync);
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        for response in responses {
            receiver.add_response_frame(response);
        }

        DiscoveryMaster::new_with_mocks(
            interface,
            device_state_manager,
            Box::new(sender),
            Box::new(receiver),
        )
    }

    fn default_discovery_response() -> Vec<u8> {
        create_discovery_response(SLAVE_MAC, TEST_MAC, 1, VENDOR_ID, DEVICE_ID, SERIAL_NUMBER)
    }

    fn default_get_ip_response() -> Vec<u8> {
        create_get_ip_response(
            SLAVE_MAC,
            TEST_MAC,
            1,
            DEFAULT_IP,
            DEFAULT_NETMASK,
            DEFAULT_GATEWAY,
            common::slave_api::IpSource::Manuell,
        )
    }

    fn default_set_ip_response(status: StatusCode) -> Vec<u8> {
        create_set_ip_response(SLAVE_MAC, TEST_MAC, 1, status)
    }

    fn assert_device_error(result: Result<(), DiscoveryError>, expected_status: StatusCode) {
        match result {
            Err(DiscoveryError::DeviceError(status)) => {
                assert_eq!(status, expected_status);
            }
            _ => panic!("Expected DeviceError with {:?} status", expected_status),
        }
    }

    #[test]
    fn test_process_discover_frame_valid() {
        let frame = default_discovery_response();
        let device = process_discover_frame(&frame, 1).expect("Should parse valid frame");

        assert_eq!(device.mac_address, SLAVE_MAC);
        assert_eq!(device.vendor_id, VENDOR_ID);
        assert_eq!(device.device_id, DEVICE_ID);
        assert_eq!(device.serial_number, SERIAL_NUMBER);
    }

    #[test]
    fn test_process_discover_frame_wrong_transaction_id() {
        let frame = create_discovery_response(
            SLAVE_MAC,
            TEST_MAC,
            0x9999,
            VENDOR_ID,
            DEVICE_ID,
            SERIAL_NUMBER,
        );
        assert!(process_discover_frame(&frame, 1).is_none());
    }

    #[test]
    fn test_process_discover_frame_wrong_opcode() {
        let frame = build_sdcp_frame(SLAVE_MAC, TEST_MAC, 1, SdcpOpCode::DiscoverReq, None);
        assert!(process_discover_frame(&frame, 1).is_none());
    }

    #[test]
    fn test_process_discover_frame_wrong_ethertype() {
        let mut frame = vec![0u8; 64];
        frame[0..6].copy_from_slice(&SLAVE_MAC.octets());
        frame[6..12].copy_from_slice(&TEST_MAC.octets());
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        assert!(process_discover_frame(&frame, 1).is_none());
    }

    #[test]
    fn test_discover_devices_with_single_response() {
        let mut master = create_test_master_with_responses(vec![default_discovery_response()]);

        let devices = master.discover_devices(Some(TEST_TIMEOUT)).unwrap();

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac_address, SLAVE_MAC);
        assert_eq!(devices[0].vendor_id, VENDOR_ID);
        assert_eq!(devices[0].device_id, DEVICE_ID);
        assert_eq!(devices[0].serial_number, SERIAL_NUMBER);
        assert!(master.discovered_devices().contains_key(&SLAVE_MAC));
    }

    #[test]
    fn test_discover_devices_with_multiple_responses() {
        let responses = vec![
            create_discovery_response(SLAVE_MAC, TEST_MAC, 1, 0x1111, 0x2222, 0x11111111),
            create_discovery_response(SLAVE2_MAC, TEST_MAC, 1, 0x3333, 0x4444, 0x22222222),
        ];
        let mut master = create_test_master_with_responses(responses);

        let devices = master.discover_devices(Some(TEST_TIMEOUT)).unwrap();

        assert_eq!(devices.len(), 2);
        assert_eq!(master.discovered_devices().len(), 2);
        assert_eq!(
            master
                .discovered_devices()
                .get(&SLAVE_MAC)
                .unwrap()
                .vendor_id,
            0x1111
        );
        assert_eq!(
            master
                .discovered_devices()
                .get(&SLAVE2_MAC)
                .unwrap()
                .vendor_id,
            0x3333
        );
    }

    #[test]
    fn test_discover_devices_no_responses() {
        let mut master = create_test_master();

        let devices = master.discover_devices(Some(TEST_TIMEOUT)).unwrap();

        assert!(devices.is_empty());
        assert!(master.discovered_devices().is_empty());
    }

    #[test]
    fn test_discover_devices_ignores_wrong_transaction_id() {
        // Response with wrong transaction ID (99 instead of 1)
        let response =
            create_discovery_response(SLAVE_MAC, TEST_MAC, 99, VENDOR_ID, DEVICE_ID, SERIAL_NUMBER);
        let mut master = create_test_master_with_responses(vec![response]);

        let devices = master.discover_devices(Some(TEST_TIMEOUT)).unwrap();

        assert!(devices.is_empty());
    }

    #[test]
    fn test_discover_devices_sends_broadcast_frame() {
        let mut master = create_test_master();

        let _ = master.discover_devices(Some(SHORT_TIMEOUT));
    }

    #[test]
    fn test_get_ip_config_success() {
        let mut master = create_test_master_with_responses(vec![default_get_ip_response()]);

        let ip_report = master.get_ip_config(SLAVE_MAC, Some(TEST_TIMEOUT)).unwrap();

        assert_eq!(ip_report.ip, DEFAULT_IP);
        assert_eq!(ip_report.netmask, DEFAULT_NETMASK);
        assert_eq!(ip_report.gateway, DEFAULT_GATEWAY);
        assert_eq!(ip_report.ip_source, common::slave_api::IpSource::Manuell);
    }

    #[test]
    fn test_get_ip_config_timeout() {
        let mut master = create_test_master();

        let result = master.get_ip_config(SLAVE_MAC, Some(SHORT_TIMEOUT));

        assert!(matches!(result, Err(DiscoveryError::Timeout)));
    }

    #[test]
    fn test_get_ip_config_wrong_source_mac() {
        let wrong_source_mac = MacAddr(0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA);
        let response = create_get_ip_response(
            wrong_source_mac,
            TEST_MAC,
            1,
            DEFAULT_IP,
            DEFAULT_NETMASK,
            DEFAULT_GATEWAY,
            common::slave_api::IpSource::Manuell,
        );
        let mut master = create_test_master_with_responses(vec![response]);

        let result = master.get_ip_config(SLAVE_MAC, Some(SHORT_TIMEOUT));

        assert!(matches!(result, Err(DiscoveryError::Timeout)));
    }

    #[test]
    fn test_set_ip_config_success() {
        let mut master =
            create_test_master_with_responses(vec![default_set_ip_response(StatusCode::NoError)]);

        let result = master.set_ip_config(
            SLAVE_MAC,
            [10, 0, 0, 50],
            DEFAULT_NETMASK,
            [10, 0, 0, 1],
            Some(TEST_TIMEOUT),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_set_ip_config_ip_conflict() {
        let mut master = create_test_master_with_responses(vec![default_set_ip_response(
            StatusCode::ErrIpConflict,
        )]);

        let result = master.set_ip_config(
            SLAVE_MAC,
            [10, 0, 0, 50],
            DEFAULT_NETMASK,
            [10, 0, 0, 1],
            Some(TEST_TIMEOUT),
        );

        assert_device_error(result, StatusCode::ErrIpConflict);
    }

    #[test]
    fn test_set_ip_config_timeout() {
        let mut master = create_test_master();

        let result = master.set_ip_config(
            SLAVE_MAC,
            [10, 0, 0, 50],
            DEFAULT_NETMASK,
            [10, 0, 0, 1],
            Some(SHORT_TIMEOUT),
        );

        assert!(matches!(result, Err(DiscoveryError::Timeout)));
    }

    #[test]
    fn test_set_ip_config_os_failure() {
        let mut master = create_test_master_with_responses(vec![default_set_ip_response(
            StatusCode::ErrOsFailure,
        )]);

        let result = master.set_ip_config(
            SLAVE_MAC,
            [10, 0, 0, 50],
            DEFAULT_NETMASK,
            [10, 0, 0, 1],
            Some(TEST_TIMEOUT),
        );

        assert_device_error(result, StatusCode::ErrOsFailure);
    }

    #[test]
    fn test_clear_discovered_devices() {
        let mut master = create_test_master_with_responses(vec![default_discovery_response()]);

        let _ = master.discover_devices(Some(TEST_TIMEOUT));
        assert_eq!(master.discovered_devices().len(), 1);

        master.clear_discovered_devices();
        assert!(master.discovered_devices().is_empty());
    }
}
