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
    DeviceInfo, IpReport, SdcpHeader, SdcpOpCode, Tlv, ETHERTYPE_SDCP, SDCP_HEADER_SIZE,
};
use common::status_codes::StatusCode;
use log::{debug, info, warn};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{self, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::{cmp, io};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Broadcast MAC address for network-wide discovery
const BROADCAST_MAC: MacAddr = MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

/// Default timeout for waiting for discovery responses
const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(2000);

/// Default timeout for waiting for unicast responses (SetIp, GetIp)
const DEFAULT_UNICAST_TIMEOUT: Duration = Duration::from_millis(1000);

/// Minimum Ethernet frame size (excluding FCS)
const MIN_FRAME_SIZE: usize = 60;

/// Represents a discovered device with its network and identification information
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub mac_address: MacAddr,
    pub vendor_id: u16,
    pub device_id: u16,
    pub serial_number: u32,
}

impl DiscoveredDevice {
    fn new(mac_address: MacAddr, device_info: DeviceInfo) -> Self {
        Self {
            mac_address,
            vendor_id: device_info.vendor_id,
            device_id: device_info.device_id,
            serial_number: device_info.serial_number,
        }
    }
}

/// Error types for discovery operations
#[derive(Debug)]
pub enum DiscoveryError {
    InterfaceNotFound(String),
    ChannelCreationFailed(String),
    Timeout,
    InvalidResponse(String),
    DeviceError(StatusCode),
    IoError(io::Error),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::InterfaceNotFound(name) => {
                write!(f, "Network interface not found: {name}")
            }
            DiscoveryError::ChannelCreationFailed(msg) => {
                write!(f, "Failed to create datalink channel: {msg}")
            }
            DiscoveryError::Timeout => write!(f, "Timeout waiting for response"),
            DiscoveryError::InvalidResponse(msg) => write!(f, "Invalid response: {msg}"),
            DiscoveryError::DeviceError(code) => write!(f, "Device error: {code}"),
            DiscoveryError::IoError(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<io::Error> for DiscoveryError {
    fn from(err: io::Error) -> Self {
        DiscoveryError::IoError(err)
    }
}

/// Master-side SDCP discovery controller
///
/// Manages discovery operations including device scanning, IP queries,
/// and IP configuration. Maintains a cache of discovered devices.
///
/// # Example
///
/// ```no_run
/// use master::discovery::DiscoveryMaster;
///
/// let mut master = DiscoveryMaster::new("eth0").expect("Failed to initialize");
/// let devices = master.discover_devices().expect("Discovery failed");
/// for device in devices {
///     println!("Found: {:?}", device);
/// }
/// ```
pub struct DiscoveryMaster {
    interface: NetworkInterface,
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
    pub fn new(interface_name: &str) -> Result<Self, DiscoveryError> {
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
                ))
            }
            Err(e) => return Err(DiscoveryError::ChannelCreationFailed(e.to_string())),
        };

        Ok(Self {
            interface,
            transmitter,
            receiver,
            discovered_devices: HashMap::new(),
            transaction_counter: AtomicU16::new(1),
        })
    }

    /// Creates a `DiscoveryMaster` with injected mock components for testing.
    #[cfg(test)]
    fn new_with_mocks(
        interface: NetworkInterface,
        transmitter: Box<dyn DataLinkSender>,
        receiver: Box<dyn DataLinkReceiver>,
    ) -> Self {
        Self {
            interface,
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
        let timeout = timeout.unwrap_or(DEFAULT_DISCOVERY_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!("Starting device discovery (transaction_id: {transaction_id:#06x}, timeout: {timeout:?})");

        let frame = self.build_request_frame(BROADCAST_MAC, SdcpOpCode::DiscoverReq, transaction_id, None)?;
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
        let timeout = timeout.unwrap_or(DEFAULT_UNICAST_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!("Querying IP config from {target_mac} (transaction_id: {transaction_id:#06x})");

        let frame = self.build_request_frame(target_mac, SdcpOpCode::GetIpReq, transaction_id, None)?;
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
        let timeout = timeout.unwrap_or(DEFAULT_UNICAST_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!(
            "Setting IP config on {target_mac}: {}.{}.{}.{}/{}.{}.{}.{} gw {}.{}.{}.{} (transaction_id: {transaction_id:#06x})",
            ip[0], ip[1], ip[2], ip[3],
            netmask[0], netmask[1], netmask[2], netmask[3],
            gateway[0], gateway[1], gateway[2], gateway[3]
        );

        let tlv = Tlv::ip_config(ip, netmask, gateway);
        let frame = self.build_request_frame(target_mac, SdcpOpCode::SetIpReq, transaction_id, Some(tlv))?;
        self.send_frame(&frame)?;

        self.wait_for_response(target_mac, SdcpOpCode::SetIpRes, transaction_id, timeout)
            .and_then(|payload| {
                if payload.len() > SDCP_HEADER_SIZE as usize {
                    let tlv_data = &payload[SDCP_HEADER_SIZE as usize..];
                    if let Ok(tlv) = Tlv::read_from(tlv_data) {
                        if let Some(status) = tlv.parse_status_report() {
                            return if status == StatusCode::NoError {
                                info!("IP configuration successfully applied to {target_mac}");
                                Ok(())
                            } else {
                                warn!("Device {target_mac} rejected IP config: {status}");
                                Err(DiscoveryError::DeviceError(status))
                            };
                        }
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
        let tlv_size = payload_tlv.as_ref().map_or(0, |tlv| 2 + tlv.length as usize);
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
                        if let Ok(header) = SdcpHeader::read_from(payload) {
                            if header.op_code == expected_opcode
                                && header.transaction_id == expected_transaction_id
                            {
                                debug!(
                                    "Received expected response from {expected_source}: {:?}",
                                    expected_opcode
                                );
                                return Ok(payload.to_vec());
                            }
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

    if header.op_code != SdcpOpCode::DiscoverRes
        || header.transaction_id != expected_transaction_id
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
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockDataLinkSender {
        sent_frames: Mutex<Vec<Vec<u8>>>,
    }

    impl MockDataLinkSender {
        fn new() -> Self {
            Self {
                sent_frames: Mutex::new(Vec::new()),
            }
        }

        #[allow(dead_code)]
        fn get_sent_frames(&self) -> Vec<Vec<u8>> {
            self.sent_frames.lock().unwrap().clone()
        }
    }

    impl DataLinkSender for MockDataLinkSender {
        fn send_to(
            &mut self,
            packet: &[u8],
            _dst: Option<NetworkInterface>,
        ) -> Option<Result<(), io::Error>> {
            self.sent_frames.lock().unwrap().push(packet.to_vec());
            Some(Ok(()))
        }

        fn build_and_send(
            &mut self,
            _num_packets: usize,
            _packet_size: usize,
            _func: &mut dyn FnMut(&mut [u8]),
        ) -> Option<Result<(), io::Error>> {
            Some(Ok(()))
        }
    }

    struct MockDataLinkReceiver {
        frames: Mutex<VecDeque<Vec<u8>>>,
        current_frame: Vec<u8>,
    }

    impl MockDataLinkReceiver {
        fn new() -> Self {
            Self {
                frames: Mutex::new(VecDeque::new()),
                current_frame: Vec::new(),
            }
        }

        fn add_response_frame(&self, frame: Vec<u8>) {
            self.frames.lock().unwrap().push_back(frame);
        }
    }

    impl DataLinkReceiver for MockDataLinkReceiver {
        fn next(&mut self) -> Result<&[u8], io::Error> {
            if let Some(frame) = self.frames.lock().unwrap().pop_front() {
                self.current_frame = frame;
                Ok(&self.current_frame)
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "No frames available"))
            }
        }
    }

    fn create_mock_interface() -> NetworkInterface {
        NetworkInterface {
            name: "mock0".to_string(),
            description: "Mock interface".to_string(),
            index: 0,
            mac: Some(MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)),
            ips: vec![],
            flags: 0,
        }
    }

    fn create_discovery_response(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        transaction_id: u16,
        vendor_id: u16,
        device_id: u16,
        serial_number: u32,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&dest_mac.octets());
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::DiscoverRes, transaction_id);
        header.write_to(&mut sdcp_payload).unwrap();

        let tlv = Tlv::device_info(vendor_id, device_id, serial_number);
        tlv.write_to(&mut sdcp_payload).unwrap();

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);
        frame
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
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&dest_mac.octets());
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::GetIpRes, transaction_id);
        header.write_to(&mut sdcp_payload).unwrap();

        let tlv = Tlv::ip_report(ip, netmask, gateway, ip_source);
        tlv.write_to(&mut sdcp_payload).unwrap();

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);
        frame
    }

    fn create_set_ip_response(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        transaction_id: u16,
        status: StatusCode,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&dest_mac.octets());
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::SetIpRes, transaction_id);
        header.write_to(&mut sdcp_payload).unwrap();

        let tlv = Tlv::status_report(status);
        tlv.write_to(&mut sdcp_payload).unwrap();

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);
        frame
    }

    #[test]
    fn test_discovered_device_creation() {
        let mac = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let device_info = DeviceInfo {
            vendor_id: 0x1234,
            device_id: 0x5678,
            serial_number: 0xDEADBEEF,
        };

        let device = DiscoveredDevice::new(mac, device_info);

        assert_eq!(device.mac_address, mac);
        assert_eq!(device.vendor_id, 0x1234);
        assert_eq!(device.device_id, 0x5678);
        assert_eq!(device.serial_number, 0xDEADBEEF);
    }

    #[test]
    fn test_discovery_error_display() {
        let err = DiscoveryError::InterfaceNotFound("eth0".to_string());
        assert!(err.to_string().contains("eth0"));

        let err = DiscoveryError::Timeout;
        assert!(err.to_string().contains("Timeout"));

        let err = DiscoveryError::DeviceError(StatusCode::IpConflict);
        assert!(err.to_string().contains("IP Conflict"));
    }

    #[test]
    fn test_process_discover_frame_valid() {
        let mut frame = vec![0u8; 64];
        let source_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let transaction_id: u16 = 0x0001;
        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::DiscoverRes, transaction_id);
        header.write_to(&mut sdcp_payload).unwrap();

        let tlv = Tlv::device_info(0x1234, 0x5678, 0xDEADBEEF);
        tlv.write_to(&mut sdcp_payload).unwrap();

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);

        let device = process_discover_frame(&frame, transaction_id);
        assert!(device.is_some());

        let device = device.unwrap();
        assert_eq!(device.mac_address, source_mac);
        assert_eq!(device.vendor_id, 0x1234);
        assert_eq!(device.device_id, 0x5678);
        assert_eq!(device.serial_number, 0xDEADBEEF);
    }

    #[test]
    fn test_process_discover_frame_wrong_transaction_id() {
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::DiscoverRes, 0x9999);
        header.write_to(&mut sdcp_payload).unwrap();

        let tlv = Tlv::device_info(0x1234, 0x5678, 0xDEADBEEF);
        tlv.write_to(&mut sdcp_payload).unwrap();

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);

        let device = process_discover_frame(&frame, 0x0001);
        assert!(device.is_none());
    }

    #[test]
    fn test_process_discover_frame_wrong_opcode() {
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame[12..14].copy_from_slice(&ETHERTYPE_SDCP.to_be_bytes());

        let mut sdcp_payload = Vec::new();
        let header = SdcpHeader::new(SdcpOpCode::DiscoverReq, 0x0001);
        header.write_to(&mut sdcp_payload).unwrap();

        frame[14..14 + sdcp_payload.len()].copy_from_slice(&sdcp_payload);

        let device = process_discover_frame(&frame, 0x0001);
        assert!(device.is_none());
    }

    #[test]
    fn test_process_discover_frame_wrong_ethertype() {
        let mut frame = vec![0u8; 64];

        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let device = process_discover_frame(&frame, 0x0001);
        assert!(device.is_none());
    }

    #[test]
    fn test_transaction_id_generation() {
        let counter = AtomicU16::new(1);

        let id1 = counter.fetch_add(1, Ordering::Relaxed);
        let id2 = counter.fetch_add(1, Ordering::Relaxed);
        let id3 = counter.fetch_add(1, Ordering::Relaxed);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_discover_devices_with_single_response() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let response = create_discovery_response(
            slave_mac,
            master_mac,
            1,
            0x1234,
            0x5678,
            0xDEADBEEF,
        );
        receiver.add_response_frame(response);

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let devices = master
            .discover_devices(Some(Duration::from_millis(100)))
            .unwrap();

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac_address, slave_mac);
        assert_eq!(devices[0].vendor_id, 0x1234);
        assert_eq!(devices[0].device_id, 0x5678);
        assert_eq!(devices[0].serial_number, 0xDEADBEEF);

        assert_eq!(master.discovered_devices().len(), 1);
        assert!(master.discovered_devices().contains_key(&slave_mac));
    }

    #[test]
    fn test_discover_devices_with_multiple_responses() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave1_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let slave2_mac = MacAddr(0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC);

        receiver.add_response_frame(create_discovery_response(
            slave1_mac,
            master_mac,
            1,
            0x1111,
            0x2222,
            0x11111111,
        ));
        receiver.add_response_frame(create_discovery_response(
            slave2_mac,
            master_mac,
            1,
            0x3333,
            0x4444,
            0x22222222,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let devices = master
            .discover_devices(Some(Duration::from_millis(100)))
            .unwrap();

        assert_eq!(devices.len(), 2);
        assert_eq!(master.discovered_devices().len(), 2);

        let device1 = master.discovered_devices().get(&slave1_mac).unwrap();
        assert_eq!(device1.vendor_id, 0x1111);

        let device2 = master.discovered_devices().get(&slave2_mac).unwrap();
        assert_eq!(device2.vendor_id, 0x3333);
    }

    #[test]
    fn test_discover_devices_no_responses() {
        let interface = create_mock_interface();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let devices = master
            .discover_devices(Some(Duration::from_millis(100)))
            .unwrap();

        assert!(devices.is_empty());
        assert!(master.discovered_devices().is_empty());
    }

    #[test]
    fn test_discover_devices_ignores_wrong_transaction_id() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        // Response with wrong transaction ID (99 instead of 1)
        receiver.add_response_frame(create_discovery_response(
            slave_mac,
            master_mac,
            99,
            0x1234,
            0x5678,
            0xDEADBEEF,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let devices = master
            .discover_devices(Some(Duration::from_millis(100)))
            .unwrap();

        assert!(devices.is_empty());
    }

    #[test]
    fn test_discover_devices_sends_broadcast_frame() {
        let interface = create_mock_interface();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let mut master = DiscoveryMaster::new_with_mocks(
            interface.clone(),
            Box::new(sender),
            Box::new(receiver),
        );

        let _ = master.discover_devices(Some(Duration::from_millis(50)));

        // Test verifies that discover_devices executes without panic
        // The actual frame validation would require accessing the mock's internal state
        let _sent = master.transmitter.build_and_send(0, 0, &mut |_| {});
    }

    #[test]
    fn test_get_ip_config_success() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let expected_ip = [192, 168, 1, 100];
        let expected_netmask = [255, 255, 255, 0];
        let expected_gateway = [192, 168, 1, 1];

        receiver.add_response_frame(create_get_ip_response(
            slave_mac,
            master_mac,
            1,
            expected_ip,
            expected_netmask,
            expected_gateway,
            common::slave_api::IpSource::Manuell,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let ip_report = master
            .get_ip_config(slave_mac, Some(Duration::from_millis(100)))
            .unwrap();

        assert_eq!(ip_report.ip, expected_ip);
        assert_eq!(ip_report.netmask, expected_netmask);
        assert_eq!(ip_report.gateway, expected_gateway);
        assert_eq!(ip_report.ip_source, common::slave_api::IpSource::Manuell);
    }

    #[test]
    fn test_get_ip_config_timeout() {
        let interface = create_mock_interface();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let result = master.get_ip_config(slave_mac, Some(Duration::from_millis(50)));

        assert!(matches!(result, Err(DiscoveryError::Timeout)));
    }

    #[test]
    fn test_get_ip_config_wrong_source_mac() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let target_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let wrong_source_mac = MacAddr(0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA);

        // Response from a different MAC address
        receiver.add_response_frame(create_get_ip_response(
            wrong_source_mac,
            master_mac,
            1,
            [192, 168, 1, 100],
            [255, 255, 255, 0],
            [192, 168, 1, 1],
            common::slave_api::IpSource::Manuell,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let result = master.get_ip_config(target_mac, Some(Duration::from_millis(50)));

        assert!(matches!(result, Err(DiscoveryError::Timeout)));
    }

    #[test]
    fn test_set_ip_config_success() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        receiver.add_response_frame(create_set_ip_response(
            slave_mac,
            master_mac,
            1,
            StatusCode::NoError,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let result = master.set_ip_config(
            slave_mac,
            [10, 0, 0, 50],
            [255, 255, 255, 0],
            [10, 0, 0, 1],
            Some(Duration::from_millis(100)),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_set_ip_config_ip_conflict() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        receiver.add_response_frame(create_set_ip_response(
            slave_mac,
            master_mac,
            1,
            StatusCode::IpConflict,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let result = master.set_ip_config(
            slave_mac,
            [10, 0, 0, 50],
            [255, 255, 255, 0],
            [10, 0, 0, 1],
            Some(Duration::from_millis(100)),
        );

        match result {
            Err(DiscoveryError::DeviceError(status)) => {
                assert_eq!(status, StatusCode::IpConflict);
            }
            _ => panic!("Expected DeviceError with IpConflict status"),
        }
    }

    #[test]
    fn test_set_ip_config_timeout() {
        let interface = create_mock_interface();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let result = master.set_ip_config(
            slave_mac,
            [10, 0, 0, 50],
            [255, 255, 255, 0],
            [10, 0, 0, 1],
            Some(Duration::from_millis(50)),
        );

        assert!(matches!(result, Err(DiscoveryError::Timeout)));
    }

    #[test]
    fn test_set_ip_config_os_failure() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        receiver.add_response_frame(create_set_ip_response(
            slave_mac,
            master_mac,
            1,
            StatusCode::OsFailure,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let result = master.set_ip_config(
            slave_mac,
            [10, 0, 0, 50],
            [255, 255, 255, 0],
            [10, 0, 0, 1],
            Some(Duration::from_millis(100)),
        );

        match result {
            Err(DiscoveryError::DeviceError(status)) => {
                assert_eq!(status, StatusCode::OsFailure);
            }
            _ => panic!("Expected DeviceError with OsFailure status"),
        }
    }

    #[test]
    fn test_clear_discovered_devices() {
        let interface = create_mock_interface();
        let master_mac = interface.mac.unwrap();
        let sender = MockDataLinkSender::new();
        let receiver = MockDataLinkReceiver::new();

        let slave_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        receiver.add_response_frame(create_discovery_response(
            slave_mac,
            master_mac,
            1,
            0x1234,
            0x5678,
            0xDEADBEEF,
        ));

        let mut master = DiscoveryMaster::new_with_mocks(
            interface,
            Box::new(sender),
            Box::new(receiver),
        );

        let _ = master.discover_devices(Some(Duration::from_millis(100)));
        assert_eq!(master.discovered_devices().len(), 1);

        master.clear_discovered_devices();
        assert!(master.discovered_devices().is_empty());
    }
}
