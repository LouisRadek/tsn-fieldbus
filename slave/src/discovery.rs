#![allow(dead_code)]
//! SDCP Discovery Listener Implementation
//!
//! This module implements the slave-side SDCP discovery protocol handler.
//! It listens for incoming SDCP discovery requests on a network interface
//! and responds with device information and IP configuration.
//!
//! # Supported Operations
//!
//! - `DiscoverReq/Res`: Respond with device identification information
//! - `GetIpReq/Res`: Report current IP configuration and source
//! - `SetIpReq/Res`: Set new IP configuration

use common::discovery_types::{ETHERTYPE_SDCP, SDCP_HEADER_SIZE, SdcpHeader, SdcpOpCode, Tlv};
use common::slave_api::IpSource;
use common::status_codes::StatusCode;
use log::{info, warn};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{self, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::sync::Arc;
use std::{cmp, thread};

use crate::hardware_abstraction::{DeviceInfoAccess, NetworkInterfaceAccess};

/// Starts a discovery listener that responds to SDCP discovery requests.
///
/// Opens a raw socket on the specified interface to listen for incoming SDCP frames.
/// Spawns a background thread that processes discovery requests and sends responses.
///
/// # Arguments
/// * `interface_name` - Network interface to listen on (e.g., "eth0")
/// * `device_info_access` - Trait object implementing `DeviceInfoAccess` for reading/writing device info
pub fn start_discovery_listener(
    interface_name: &str,
    device_info_access: Arc<dyn DeviceInfoAccess>,
    network_interface_access: Arc<dyn NetworkInterfaceAccess>,
) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .expect("Could not find network interface");

    info!(
        "Starting Discovery Listener on interface: {}",
        interface.name
    );

    let (mut transmitter, mut receiver) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(transmitter, receiver)) => (transmitter, receiver),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {e}"),
    };

    thread::spawn(move || {
        loop {
            match receiver.next() {
                Ok(packet) => {
                    let ethernet_frame = EthernetPacket::new(packet).unwrap();
                    if ethernet_frame.get_ethertype().0 != ETHERTYPE_SDCP {
                        continue;
                    }

                    let payload = ethernet_frame.payload();
                    if let Ok(header) = SdcpHeader::read_from(payload) {
                        handle_packet(
                            &header,
                            payload,
                            &ethernet_frame,
                            &mut *transmitter,
                            &interface,
                            &device_info_access,
                            &network_interface_access,
                        );
                    }
                }
                Err(e) => warn!("Failed to read packet: {e}"),
            }
        }
    });
}

/// Handles incoming SDCP packets and generates appropriate responses.
///
/// This function processes discovery protocol messages and sends responses
/// back through the provided transmitter.
///
/// # Arguments
///
/// * `header` - Parsed SDCP header from the incoming packet
/// * `raw_payload` - Raw SDCP payload bytes (including header)
/// * `ethernet_frame` - The complete Ethernet frame for extracting source MAC
/// * `transmitter` - Network transmitter for sending responses
/// * `interface` - Local network interface information
/// * `device_info_access` - Access to device identification and configuration
/// * `network_interface_access` - Access to network interface configuration
///
/// # Visibility
///
/// This function is public when the `test-utils` feature is enabled,
/// allowing integration tests to directly invoke packet handling.
#[cfg(feature = "test-utils")]
pub fn handle_packet(
    header: &SdcpHeader,
    raw_payload: &[u8],
    ethernet_frame: &EthernetPacket,
    transmitter: &mut dyn datalink::DataLinkSender,
    interface: &NetworkInterface,
    device_info_access: &Arc<dyn DeviceInfoAccess>,
    network_interface_access: &Arc<dyn NetworkInterfaceAccess>,
) {
    match header.op_code {
        SdcpOpCode::DiscoverReq => {
            info!("Received DISCOVER_REQ from {}", ethernet_frame.get_source());

            let device_info = device_info_access.read_device_info();
            let tlv = Tlv::device_info(
                device_info.vendor_id as u16,
                device_info.device_id as u16,
                device_info.serial_number,
            );

            send_response(
                transmitter,
                interface,
                ethernet_frame.get_source(),
                SdcpOpCode::DiscoverRes,
                header.transaction_id,
                tlv,
            );
        }
        SdcpOpCode::SetIpReq => {
            if raw_payload.len() > 5
                && let Ok(tlv) = Tlv::read_from(&raw_payload[5..])
                && let Some(ip_config) = tlv.parse_ip_config()
            {
                info!("Received IP Config: {ip_config:?}");

                match network_interface_access.apply_ip_config(
                    ip_config.ip,
                    ip_config.netmask,
                    ip_config.gateway,
                ) {
                    Ok(_) => {
                        info!("Successfully applied IP configuration to network interface");

                        let mut device_info = device_info_access.read_device_info();
                        device_info.ip_address = ip_config.ip.to_vec();
                        device_info.netmask = ip_config.netmask.to_vec();
                        device_info.gateway = ip_config.gateway.to_vec();
                        device_info_access.write_device_info(device_info);

                        let status_tlv = Tlv::status_report(StatusCode::NoError);
                        send_response(
                            transmitter,
                            interface,
                            ethernet_frame.get_source(),
                            SdcpOpCode::SetIpRes,
                            header.transaction_id,
                            status_tlv,
                        );
                    }
                    Err(e) => {
                        warn!("Failed to apply IP configuration: {e}");

                        let status_tlv = Tlv::status_report(StatusCode::OsFailure);
                        send_response(
                            transmitter,
                            interface,
                            ethernet_frame.get_source(),
                            SdcpOpCode::SetIpRes,
                            header.transaction_id,
                            status_tlv,
                        );
                    }
                }
            }
        }
        SdcpOpCode::GetIpReq => {
            info!(
                "Received Get IP request from: {}",
                ethernet_frame.get_source()
            );

            let device_info = device_info_access.read_device_info();

            let ip: [u8; 4] = device_info
                .ip_address
                .as_slice()
                .try_into()
                .unwrap_or([0, 0, 0, 0]);
            let netmask: [u8; 4] = device_info
                .netmask
                .as_slice()
                .try_into()
                .unwrap_or([255, 255, 255, 0]);
            let gateway: [u8; 4] = device_info
                .gateway
                .as_slice()
                .try_into()
                .unwrap_or([0, 0, 0, 0]);
            let ip_source =
                IpSource::try_from(device_info.ip_source).unwrap_or(IpSource::Unspecified);

            let tlv = Tlv::ip_report(ip, netmask, gateway, ip_source);

            send_response(
                transmitter,
                interface,
                ethernet_frame.get_source(),
                SdcpOpCode::GetIpRes,
                header.transaction_id,
                tlv,
            );
        }
        _ => {}
    }
}

fn send_response(
    tx: &mut dyn datalink::DataLinkSender,
    interface: &NetworkInterface,
    target_mac: MacAddr,
    op_code: SdcpOpCode,
    transaction_id: u16,
    payload_tlv: Tlv,
) {
    // Ethernet Header (14 bytes), SDCP Header Size, TLV Lenght, 2 for the type and lenght field of the tlv
    let required_buffer_size = 14 + SDCP_HEADER_SIZE + payload_tlv.length + 2;
    let mut buffer = vec![0u8; cmp::max(required_buffer_size as usize, 60)];

    let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
    eth.set_destination(target_mac);
    eth.set_source(interface.mac.unwrap());
    eth.set_ethertype(ethernet::EtherType(ETHERTYPE_SDCP));

    let mut payload_buffer = Vec::new();
    let header = SdcpHeader::new(op_code, transaction_id);
    header.write_to(&mut payload_buffer).unwrap();
    payload_tlv.write_to(&mut payload_buffer).unwrap();

    eth.set_payload(&payload_buffer);

    let immutable = eth.to_immutable();
    tx.send_to(immutable.packet(), None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::slave_api::{DeviceInfo, IpSource};
    use std::sync::{Arc, Mutex};

    struct MockDeviceInfoAccess {
        device_info: Mutex<DeviceInfo>,
    }

    impl MockDeviceInfoAccess {
        fn new() -> Self {
            Self {
                device_info: Mutex::new(DeviceInfo {
                    mac_address: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
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
    }

    impl DeviceInfoAccess for MockDeviceInfoAccess {
        fn read_device_info(&self) -> DeviceInfo {
            self.device_info.lock().unwrap().clone()
        }

        fn write_device_info(&self, info: DeviceInfo) {
            *self.device_info.lock().unwrap() = info;
        }
    }

    struct MockNetworkInterfaceAccess {
        apply_config_called: Mutex<bool>,
        apply_config_should_fail: bool,
    }

    impl MockNetworkInterfaceAccess {
        fn new() -> Self {
            Self {
                apply_config_called: Mutex::new(false),
                apply_config_should_fail: false,
            }
        }

        fn new_fail() -> Self {
            Self {
                apply_config_called: Mutex::new(false),
                apply_config_should_fail: true,
            }
        }

        fn was_called(&self) -> bool {
            *self.apply_config_called.lock().unwrap()
        }
    }

    impl NetworkInterfaceAccess for MockNetworkInterfaceAccess {
        fn apply_ip_config(
            &self,
            _ip: [u8; 4],
            _netmask: [u8; 4],
            _gateway: [u8; 4],
        ) -> Result<(), String> {
            *self.apply_config_called.lock().unwrap() = true;
            if self.apply_config_should_fail {
                Err("Simulated network interface failure".to_string())
            } else {
                Ok(())
            }
        }
    }

    struct MockDataLinkSender {
        sent_packets: Mutex<Vec<Vec<u8>>>,
    }

    impl MockDataLinkSender {
        fn new() -> Self {
            Self {
                sent_packets: Mutex::new(Vec::new()),
            }
        }

        fn get_sent_packets(&self) -> Vec<Vec<u8>> {
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

    #[test]
    fn test_handle_packet_discover_req() {
        let device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfoAccess::new());
        let network_access: Arc<dyn NetworkInterfaceAccess> =
            Arc::new(MockNetworkInterfaceAccess::new());
        let mut sender = MockDataLinkSender::new();

        let header = SdcpHeader::new(SdcpOpCode::DiscoverReq, 0x0001);
        let mut payload = Vec::new();
        header.write_to(&mut payload).unwrap();
        payload.extend_from_slice(&[0u8; 100]);

        let header_read = SdcpHeader::read_from(&payload).unwrap();
        assert_eq!(header_read.op_code, SdcpOpCode::DiscoverReq);

        let mut buffer = vec![0u8; 64];
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_packet.set_source(MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01));
        eth_packet.set_destination(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));

        let eth_frame = EthernetPacket::new(&buffer).unwrap();

        handle_packet(
            &header_read,
            &payload,
            &eth_frame,
            &mut sender,
            &pnet::datalink::interfaces()[0],
            &Arc::new(device_info),
            &Arc::new(network_access),
        );

        let sent = sender.get_sent_packets();
        assert!(!sent.is_empty(), "Response packet should have been sent");
        assert!(!sent[0].is_empty(), "Response packet should not be empty");
    }

    #[test]
    fn test_handle_packet_set_ip_req_success() {
        let device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfoAccess::new());
        let network_access: Arc<dyn NetworkInterfaceAccess> =
            Arc::new(MockNetworkInterfaceAccess::new());
        let mut sender = MockDataLinkSender::new();

        let ip_config = [10, 0, 0, 50];
        let netmask = [255, 255, 255, 0];
        let gateway = [10, 0, 0, 1];
        let tlv = Tlv::ip_config(ip_config, netmask, gateway);

        let header = SdcpHeader::new(SdcpOpCode::SetIpReq, 0x0002);
        let mut payload = Vec::new();
        header.write_to(&mut payload).unwrap();
        tlv.write_to(&mut payload).unwrap();

        let mut buffer = vec![0u8; 64];
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_packet.set_source(MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02));
        eth_packet.set_destination(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));

        let eth_frame = EthernetPacket::new(&buffer).unwrap();

        handle_packet(
            &header,
            &payload,
            &eth_frame,
            &mut sender,
            &pnet::datalink::interfaces()[0],
            &Arc::new(device_info.clone()),
            &Arc::new(network_access.clone()),
        );

        let sent = sender.get_sent_packets();
        assert!(!sent.is_empty(), "Response packet should have been sent");

        let updated_info = device_info.read_device_info();
        assert_eq!(updated_info.ip_address, vec![10, 0, 0, 50]);
        assert_eq!(updated_info.netmask, vec![255, 255, 255, 0]);
        assert_eq!(updated_info.gateway, vec![10, 0, 0, 1]);
    }

    #[test]
    fn test_handle_packet_set_ip_req_failure() {
        let device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfoAccess::new());
        let network_access: Arc<dyn NetworkInterfaceAccess> =
            Arc::new(MockNetworkInterfaceAccess::new_fail());
        let mut sender = MockDataLinkSender::new();

        let ip_config = [10, 0, 0, 50];
        let netmask = [255, 255, 255, 0];
        let gateway = [10, 0, 0, 1];
        let tlv = Tlv::ip_config(ip_config, netmask, gateway);

        let header = SdcpHeader::new(SdcpOpCode::SetIpReq, 0x0003);
        let mut payload = Vec::new();
        header.write_to(&mut payload).unwrap();
        tlv.write_to(&mut payload).unwrap();

        let mut buffer = vec![0u8; 64];
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_packet.set_source(MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03));
        eth_packet.set_destination(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));

        let eth_frame = EthernetPacket::new(&buffer).unwrap();

        handle_packet(
            &header,
            &payload,
            &eth_frame,
            &mut sender,
            &pnet::datalink::interfaces()[0],
            &Arc::new(device_info.clone()),
            &Arc::new(network_access),
        );

        let sent = sender.get_sent_packets();
        assert!(!sent.is_empty(), "Response packet should have been sent");

        let info = device_info.read_device_info();
        assert_eq!(
            info.ip_address,
            vec![192, 168, 1, 100],
            "Device info should not change on failure"
        );
    }

    #[test]
    fn test_handle_packet_get_ip_req() {
        let device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfoAccess::new());
        let network_access: Arc<dyn NetworkInterfaceAccess> =
            Arc::new(MockNetworkInterfaceAccess::new());
        let mut sender = MockDataLinkSender::new();

        let header = SdcpHeader::new(SdcpOpCode::GetIpReq, 0x0004);
        let mut payload = Vec::new();
        header.write_to(&mut payload).unwrap();
        payload.extend_from_slice(&[0u8; 100]);

        let header_read = SdcpHeader::read_from(&payload).unwrap();
        assert_eq!(header_read.op_code, SdcpOpCode::GetIpReq);

        let mut buffer = vec![0u8; 64];
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_packet.set_source(MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04));
        eth_packet.set_destination(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF));

        let eth_frame = EthernetPacket::new(&buffer).unwrap();

        handle_packet(
            &header_read,
            &payload,
            &eth_frame,
            &mut sender,
            &pnet::datalink::interfaces()[0],
            &Arc::new(device_info),
            &Arc::new(network_access),
        );

        let sent = sender.get_sent_packets();
        assert!(!sent.is_empty(), "GetIpRes packet should have been sent");
        assert!(!sent[0].is_empty(), "Response packet should not be empty");
    }

    #[test]
    fn test_send_response_creates_valid_frame() {
        let mut sender = MockDataLinkSender::new();
        let interfaces = pnet::datalink::interfaces();
        let interface = &interfaces[0];

        let tlv = Tlv::status_report(StatusCode::NoError);
        let target_mac = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99);

        send_response(
            &mut sender,
            interface,
            target_mac,
            SdcpOpCode::DiscoverRes,
            0x0001,
            tlv,
        );

        let sent = sender.get_sent_packets();
        assert!(!sent.is_empty(), "Packet should have been sent");
        assert!(
            sent[0].len() >= 14,
            "Ethernet frame must be at least 14 bytes"
        );

        let frame = EthernetPacket::new(&sent[0]).unwrap();
        assert_eq!(frame.get_destination(), target_mac);
        assert_eq!(frame.get_ethertype().0, ETHERTYPE_SDCP);
    }

    #[test]
    fn test_send_response_with_different_opcodes() {
        let interfaces = pnet::datalink::interfaces();
        let interface = &interfaces[0];

        let opcodes = [
            SdcpOpCode::DiscoverRes,
            SdcpOpCode::GetIpRes,
            SdcpOpCode::SetIpRes,
        ];

        for opcode in &opcodes {
            let mut sender = MockDataLinkSender::new();
            let tlv = Tlv::status_report(StatusCode::NoError);

            send_response(
                &mut sender,
                interface,
                MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
                *opcode,
                0x0001,
                tlv,
            );

            let sent = sender.get_sent_packets();
            assert!(
                !sent.is_empty(),
                "Packet should have been sent for opcode {opcode:?}"
            );
        }
    }

    #[test]
    fn test_device_info_persistence_across_operations() {
        let device_info = Arc::new(MockDeviceInfoAccess::new());

        // Initial state
        let initial = device_info.read_device_info();
        assert_eq!(initial.vendor_id, 0x1234);

        // Simulate IP update
        let mut updated = initial;
        updated.ip_address = vec![10, 0, 0, 1];
        device_info.write_device_info(updated);

        // Verify persistence
        let persisted = device_info.read_device_info();
        assert_eq!(persisted.ip_address, vec![10, 0, 0, 1]);
        assert_eq!(
            persisted.vendor_id, 0x1234,
            "Other fields should remain unchanged"
        );
    }
}
