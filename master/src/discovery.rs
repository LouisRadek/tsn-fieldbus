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
    DiscoveredDevice, ETHERTYPE_SDCP, IpReport, SdcpHeader, SdcpOpCode, Tlv, append_sdcp_footer,
    parse_sdcp_payload,
};
use common::security::auth_footer::SecurityFooter;
use common::security::discovery_auth::DiscoveryAuthHandler;
use common::slave_api::{DeviceState, StatusCode};
use common::state_machine::DeviceStateManager;
use log::{debug, error, info, warn};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{self, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const BROADCAST_MAC: MacAddr = MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(2000);
const DEFAULT_UNICAST_TIMEOUT: Duration = Duration::from_millis(1000);

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
    discovery_auth_handler: DiscoveryAuthHandler,
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
    /// Returns `StatusCode::ErrSocketChannel` if the interface doesn't exist or if the raw socket cannot be opened.
    pub fn new(
        interface_name: &str,
        device_state_manager: DeviceStateManager,
        shared_secret: [u8; 32],
    ) -> Result<Self, StatusCode> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.name == interface_name)
            .ok_or(StatusCode::ErrSocketChannel)?;

        info!(
            "Initializing Discovery Master on interface: {} (MAC: {:?})",
            interface.name, interface.mac
        );

        let (transmitter, receiver) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(transmitter, receiver)) => (transmitter, receiver),
            Ok(_) => {
                warn!("Unknown Channel");
                return Err(StatusCode::ErrSocketChannel);
            }
            Err(_e) => {
                error!("Error initilizing a channel");
                return Err(StatusCode::ErrSocketChannel);
            }
        };

        let discovery_auth_handler = DiscoveryAuthHandler::new(shared_secret);
        discovery_auth_handler.add_new_device(BROADCAST_MAC);

        Ok(Self {
            interface,
            device_state_manager,
            transmitter,
            receiver,
            discovered_devices: HashMap::new(),
            transaction_counter: AtomicU16::new(1),
            discovery_auth_handler,
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
        shared_secret: [u8; 32],
    ) -> Self {
        let discovery_auth_handler = DiscoveryAuthHandler::new(shared_secret);
        Self {
            interface,
            device_state_manager,
            transmitter,
            receiver,
            discovered_devices: HashMap::new(),
            transaction_counter: AtomicU16::new(1),
            discovery_auth_handler,
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
    /// Returns `StatusCode::ErrStateConflict` if packet transmission fails.
    pub fn discover_devices(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<Vec<DiscoveredDevice>, StatusCode> {
        let state = self.device_state_manager.get_state();
        if state != DeviceState::DiscoverySync {
            error!(
                "State conflict, expected {:?}, got {state:?}",
                DeviceState::DiscoverySync
            );
            return Err(StatusCode::ErrStateConflict);
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
                    if let Some(device) = process_discover_frame(
                        &frame_data,
                        transaction_id,
                        &self.discovery_auth_handler,
                    ) {
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
    /// - `StatusCode::ErrTimeout` if no response is received
    /// - `StatusCode::ErrInvalidResponse` if the response cannot be parsed
    /// - `StatusCode::StateConflict` if the device is in the wrong state
    pub fn get_ip_config(
        &mut self,
        target_mac: MacAddr,
        timeout: Option<Duration>,
    ) -> Result<IpReport, StatusCode> {
        let state = self.device_state_manager.get_state();
        if state != DeviceState::DiscoverySync {
            error!(
                "State conflict, expected {:?}, got {state:?}",
                DeviceState::DiscoverySync
            );
            return Err(StatusCode::ErrStateConflict);
        }

        let timeout = timeout.unwrap_or(DEFAULT_UNICAST_TIMEOUT);
        let transaction_id = self.next_transaction_id();

        info!("Querying IP config from {target_mac} (transaction_id: {transaction_id:#06x})");

        let frame =
            self.build_request_frame(target_mac, SdcpOpCode::GetIpReq, transaction_id, None)?;
        self.send_frame(&frame)?;

        self.wait_for_response(target_mac, SdcpOpCode::GetIpRes, transaction_id, timeout)
            .and_then(|tlv_payload| {
                Tlv::read_from(&tlv_payload)
                    .ok()
                    .and_then(|tlv| tlv.parse_ip_report())
                    .ok_or(StatusCode::ErrInvalidResponse)
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
    /// - `StatusCode::ErrTimeout` if no response is received
    /// - `StatusCode::ErrHardwareAccess` if the ip config could not be set
    /// - `StatusCode::StateConflict` if the device is in the wrong state
    /// - `StatusCode::ErrInvalidResponse` if the response can not be parsed
    pub fn set_ip_config(
        &mut self,
        target_mac: MacAddr,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
        timeout: Option<Duration>,
    ) -> Result<(), StatusCode> {
        let state = self.device_state_manager.get_state();
        if state != DeviceState::DiscoverySync {
            error!(
                "State conflict, expected {:?}, got {state:?}",
                DeviceState::DiscoverySync
            );
            return Err(StatusCode::ErrStateConflict);
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
            .and_then(|tlv_payload| {
                if let Ok(tlv) = Tlv::read_from(&tlv_payload)
                    && let Some(status) = tlv.parse_status_report()
                {
                    return if status == StatusCode::NoError {
                        info!("IP configuration successfully applied to {target_mac}");
                        Ok(())
                    } else {
                        warn!("Device {target_mac} rejected IP config: {status:?}");
                        Err(StatusCode::ErrHardwareAccess)
                    };
                }
                error!("No data in the response");
                Err(StatusCode::ErrInvalidResponse)
            })
    }

    /// Builds an SDCP request frame.
    ///
    /// Constructs a complete Ethernet frame with SDCP header and optional TLV payload.
    /// Ensures minimum frame size by padding if necessary.
    fn build_request_frame(
        &mut self,
        destination: MacAddr,
        op_code: SdcpOpCode,
        transaction_id: u16,
        payload_tlv: Option<Tlv>,
    ) -> Result<Vec<u8>, StatusCode> {
        let tlv_size = payload_tlv
            .as_ref()
            .map_or(0, |tlv| 2 + tlv.length as usize);
        let buffer_size = 14 + 5 + tlv_size + 40;

        let mut buffer = vec![0u8; buffer_size];

        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).ok_or(StatusCode::ErrOsFailure)?;

        eth_packet.set_destination(destination);
        let source_mac = self.interface.mac.ok_or(StatusCode::ErrSocketChannel)?;
        eth_packet.set_source(source_mac);
        eth_packet.set_ethertype(ethernet::EtherType(ETHERTYPE_SDCP));

        let mut payload = Vec::with_capacity(5 + tlv_size + 40);
        let header = SdcpHeader::new(op_code, transaction_id);
        header.write_to(&mut payload).map_err(|e| {
            error!("Could not write header into payload buffer: {e}");
            StatusCode::ErrOsFailure
        })?;

        let mut tlv_payload = Vec::with_capacity(tlv_size);
        if let Some(tlv) = payload_tlv {
            tlv.write_to(&mut tlv_payload).map_err(|e| {
                error!("Could not write tlv into payload buffer: {e}");
                StatusCode::ErrOsFailure
            })?;
            payload.extend_from_slice(&tlv_payload);
        }

        if !self.discovery_auth_handler.has_device(source_mac) {
            self.discovery_auth_handler.add_new_device(source_mac);
        }

        let (sequence_number, auth_tag) = self
            .discovery_auth_handler
            .create_auth_tag(source_mac, &header, &tlv_payload)
            .ok_or(StatusCode::ErrAuthFailed)?;
        append_sdcp_footer(
            &mut payload,
            &SecurityFooter {
                sequence_number,
                auth_tag,
            },
        );

        eth_packet.set_payload(&payload);

        Ok(buffer)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), StatusCode> {
        match self.transmitter.send_to(frame, None) {
            Some(Ok(_)) => {
                debug!("Frame sent successfully ({} bytes)", frame.len());
                Ok(())
            }
            Some(Err(e)) => {
                error!("Failed to send frame: {e:?}");
                Err(StatusCode::ErrSocketChannel)
            }
            None => {
                error!("Failed to send frame: transmitter returned None");
                Err(StatusCode::ErrSocketChannel)
            }
        }
    }

    /// Attempts to receive a raw Ethernet frame without blocking.
    ///
    /// Returns the complete frame data including Ethernet header,
    /// or `None` if no frame is available.
    fn receive_raw_frame_nonblocking(&mut self) -> Option<Vec<u8>> {
        match self.receiver.next() {
            Ok(data) => Some(data.to_vec()),
            Err(e) => {
                debug!("No frame received: {e}");
                None
            }
        }
    }

    fn wait_for_response(
        &mut self,
        expected_source: MacAddr,
        expected_opcode: SdcpOpCode,
        expected_transaction_id: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, StatusCode> {
        if !self.discovery_auth_handler.has_device(expected_source) {
            self.discovery_auth_handler.add_new_device(expected_source);
        }

        let start = Instant::now();

        while start.elapsed() < timeout {
            match self.receiver.next() {
                Ok(data) => {
                    if let Some(ethernet_frame) = EthernetPacket::new(data) {
                        if ethernet_frame.get_ethertype().0 != ETHERTYPE_SDCP {
                            debug!(
                                "Frame ethertype mismatch: got {}, expected {} Skipping",
                                ethernet_frame.get_ethertype().0,
                                ETHERTYPE_SDCP
                            );
                            continue;
                        }

                        if ethernet_frame.get_source() != expected_source {
                            debug!(
                                "Frame source MAC mismatch (expected: {expected_source}, got: {:?}), skipping",
                                ethernet_frame.get_source()
                            );
                            continue;
                        }

                        let payload = ethernet_frame.payload();
                        if let Ok(parsed_payload) = parse_sdcp_payload(payload)
                            && parsed_payload.header.op_code == expected_opcode
                            && parsed_payload.header.transaction_id == expected_transaction_id
                            && self.discovery_auth_handler.validate_auth_tag(
                                expected_source,
                                &parsed_payload.header,
                                parsed_payload.tlv_payload,
                                parsed_payload.sequence_number,
                                &parsed_payload.auth_tag,
                            )
                        {
                            debug!(
                                "Received expected response from {expected_source}: {expected_opcode:?}"
                            );
                            return Ok(parsed_payload.tlv_payload.to_vec());
                        } else {
                            debug!(
                                "Frame header did not match expected opcode/transaction_id or the auth tag is invalid."
                            );
                        }
                    } else {
                        warn!("Failed to parse Ethernet frame");
                    }
                }
                Err(e) => {
                    warn!("Error receiving frame: {e}");
                }
            }
        }

        error!(
            "Timeout waiting for response from {expected_source} (opcode: {expected_opcode:?}, transaction_id: {expected_transaction_id:#06x})"
        );
        Err(StatusCode::ErrTimeout)
    }
}

/// Processes a complete Ethernet frame and extracts discovered device info.
///
/// This is a helper function used during discovery to parse responses.
fn process_discover_frame(
    frame_data: &[u8],
    expected_transaction_id: u16,
    discovery_auth_handler: &DiscoveryAuthHandler,
) -> Option<DiscoveredDevice> {
    let eth_packet = EthernetPacket::new(frame_data)?;

    if eth_packet.get_ethertype().0 != ETHERTYPE_SDCP {
        return None;
    }

    let payload = eth_packet.payload();
    let parsed_payload = parse_sdcp_payload(payload).ok()?;
    let header = parsed_payload.header;

    if header.op_code != SdcpOpCode::DiscoverRes || header.transaction_id != expected_transaction_id
    {
        return None;
    }

    let source_mac = eth_packet.get_source();
    let auth_valid = if discovery_auth_handler.has_device(source_mac) {
        discovery_auth_handler.validate_auth_tag(
            source_mac,
            &header,
            parsed_payload.tlv_payload,
            parsed_payload.sequence_number,
            &parsed_payload.auth_tag,
        )
    } else {
        let valid = discovery_auth_handler.validate_discovery_response(
            &header,
            parsed_payload.tlv_payload,
            parsed_payload.sequence_number,
            &parsed_payload.auth_tag,
        );

        if valid {
            discovery_auth_handler.add_new_device(source_mac);
            discovery_auth_handler.set_last_valid_received_sequence_number(
                source_mac,
                parsed_payload.sequence_number,
            );
        }
        valid
    };

    if !auth_valid {
        return None;
    }

    let tlv_data = parsed_payload.tlv_payload;
    let tlv = Tlv::read_from(tlv_data).ok()?;
    let device_info = tlv.parse_device_info()?;

    Some(DiscoveredDevice::new(source_mac, device_info))
}
