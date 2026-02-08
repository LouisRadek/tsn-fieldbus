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
use common::hardware_abstraction::{DeviceInfoAccess, NetworkInterfaceAccess};
use common::slave_api::{DeviceInfo, IpSource, StatusCode};
use log::{info, warn};
use pnet::datalink::{self, Channel, DataLinkSender, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{self, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::sync::Arc;
use std::{cmp, thread};

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
            handle_discovery_request(
                header,
                ethernet_frame,
                transmitter,
                interface,
                device_info_access,
            );
        }
        SdcpOpCode::SetIpReq => {
            handle_set_ip_request(
                header,
                raw_payload,
                ethernet_frame,
                transmitter,
                interface,
                device_info_access,
                network_interface_access,
            );
        }
        SdcpOpCode::GetIpReq => {
            handle_get_ip_request(
                header,
                ethernet_frame,
                transmitter,
                interface,
                device_info_access,
            );
        }
        _ => {}
    }
}

fn default_device_info() -> DeviceInfo {
    DeviceInfo {
        mac_address: vec![0, 0, 0, 0, 0, 0],
        ip_address: vec![0, 0, 0, 0],
        ip_source: IpSource::Unspecified.into(),
        netmask: vec![255, 255, 255, 0],
        gateway: vec![0, 0, 0, 0],
        vendor_id: 0,
        device_id: 0,
        serial_number: 0,
        firmware_version: 0,
        capabilities: 0,
    }
}

fn send_status_response(
    transmitter: &mut dyn datalink::DataLinkSender,
    interface: &NetworkInterface,
    ethernet_frame: &EthernetPacket<'_>,
    op_code: SdcpOpCode,
    transaction_id: u16,
    code: StatusCode,
) {
    let status_tlv = Tlv::status_report(code);
    send_response(
        transmitter,
        interface,
        ethernet_frame.get_source(),
        op_code,
        transaction_id,
        status_tlv,
    );
}

fn handle_get_ip_request(
    header: &SdcpHeader,
    ethernet_frame: &EthernetPacket<'_>,
    transmitter: &mut dyn DataLinkSender,
    interface: &NetworkInterface,
    device_info_access: &Arc<dyn DeviceInfoAccess + 'static>,
) {
    info!(
        "Received Get IP request from: {}",
        ethernet_frame.get_source()
    );

    let device_info = device_info_access
        .read_device_info()
        .unwrap_or(default_device_info());

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
    let ip_source = IpSource::try_from(device_info.ip_source).unwrap_or(IpSource::Unspecified);

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

fn handle_set_ip_request(
    header: &SdcpHeader,
    raw_payload: &[u8],
    ethernet_frame: &EthernetPacket<'_>,
    transmitter: &mut dyn DataLinkSender,
    interface: &NetworkInterface,
    device_info_access: &Arc<dyn DeviceInfoAccess>,
    network_interface_access: &Arc<dyn NetworkInterfaceAccess>,
) {
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

                let mut device_info = match device_info_access.read_device_info() {
                    Ok(info) => info,
                    Err(code) => {
                        warn!("Failed to read device info: {code:?}");
                        send_status_response(
                            transmitter,
                            interface,
                            ethernet_frame,
                            SdcpOpCode::SetIpRes,
                            header.transaction_id,
                            code,
                        );
                        return;
                    }
                };
                device_info.ip_address = ip_config.ip.to_vec();
                device_info.netmask = ip_config.netmask.to_vec();
                device_info.gateway = ip_config.gateway.to_vec();
                match device_info_access.write_device_info(device_info) {
                    Ok(info) => info,
                    Err(code) => {
                        warn!("Failed to read device info: {code:?}");
                        send_status_response(
                            transmitter,
                            interface,
                            ethernet_frame,
                            SdcpOpCode::SetIpRes,
                            header.transaction_id,
                            code,
                        );
                        return;
                    }
                };

                send_status_response(
                    transmitter,
                    interface,
                    ethernet_frame,
                    SdcpOpCode::SetIpRes,
                    header.transaction_id,
                    StatusCode::NoError,
                );
            }
            Err(e) => {
                warn!("Failed to apply IP configuration: {e:?}");

                send_status_response(
                    transmitter,
                    interface,
                    ethernet_frame,
                    SdcpOpCode::SetIpRes,
                    header.transaction_id,
                    StatusCode::ErrOsFailure,
                );
            }
        }
    }
}

fn handle_discovery_request(
    header: &SdcpHeader,
    ethernet_frame: &EthernetPacket<'_>,
    transmitter: &mut dyn DataLinkSender,
    interface: &NetworkInterface,
    device_info_access: &Arc<dyn DeviceInfoAccess>,
) {
    info!("Received DISCOVER_REQ from {}", ethernet_frame.get_source());

    let device_info = device_info_access
        .read_device_info()
        .unwrap_or(default_device_info());
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
    use common::test_mocks::{MockDataLinkSender, MockDeviceInfo, MockNetworkInterface, TEST_MAC};
    use pnet::util::MacAddr;
    use std::sync::Arc;

    const MASTER_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01);
    const BROADCAST_MAC: MacAddr = MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    const TEST_IP: [u8; 4] = [10, 0, 0, 50];
    const TEST_NETMASK: [u8; 4] = [255, 255, 255, 0];
    const TEST_GATEWAY: [u8; 4] = [10, 0, 0, 1];

    struct TestContext {
        sender: MockDataLinkSender,
        device_info: Arc<dyn DeviceInfoAccess>,
        network_access: Arc<dyn NetworkInterfaceAccess>,
        interface: NetworkInterface,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                sender: MockDataLinkSender::new(),
                device_info: Arc::new(MockDeviceInfo::new(TEST_MAC)),
                network_access: Arc::new(MockNetworkInterface::new()),
                interface: pnet::datalink::interfaces()[0].clone(),
            }
        }

        fn with_failing_network() -> Self {
            Self {
                sender: MockDataLinkSender::new(),
                device_info: Arc::new(MockDeviceInfo::new(TEST_MAC)),
                network_access: Arc::new(MockNetworkInterface::failing()),
                interface: pnet::datalink::interfaces()[0].clone(),
            }
        }

        fn handle_request(&mut self, op_code: SdcpOpCode, transaction_id: u16, tlv: Option<Tlv>) {
            let (payload, header) = build_sdcp_payload(op_code, transaction_id, tlv);
            let eth_frame = create_ethernet_frame(MASTER_MAC, BROADCAST_MAC);

            handle_packet(
                &header,
                &payload,
                &EthernetPacket::new(&eth_frame).unwrap(),
                &mut self.sender,
                &self.interface,
                &self.device_info,
                &self.network_access,
            );
        }

        fn assert_response_sent(&self) {
            let sent = self.sender.get_sent_packets();
            assert!(!sent.is_empty(), "Response packet should have been sent");
            assert!(!sent[0].is_empty(), "Response packet should not be empty");
        }
    }

    fn build_sdcp_payload(
        op_code: SdcpOpCode,
        transaction_id: u16,
        tlv: Option<Tlv>,
    ) -> (Vec<u8>, SdcpHeader) {
        let header = SdcpHeader::new(op_code, transaction_id);
        let mut payload = Vec::new();
        header.write_to(&mut payload).unwrap();

        if let Some(tlv) = tlv {
            tlv.write_to(&mut payload).unwrap();
        } else {
            payload.extend_from_slice(&[0u8; 100]);
        }

        let header_read = SdcpHeader::read_from(&payload).unwrap();
        (payload, header_read)
    }

    fn create_ethernet_frame(source: MacAddr, destination: MacAddr) -> Vec<u8> {
        let mut buffer = vec![0u8; 64];
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth_packet.set_source(source);
        eth_packet.set_destination(destination);
        buffer
    }

    #[test]
    fn test_handle_packet_discover_req() {
        let mut ctx = TestContext::new();

        ctx.handle_request(SdcpOpCode::DiscoverReq, 0x0001, None);

        ctx.assert_response_sent();
    }

    #[test]
    fn test_handle_packet_set_ip_req_success() {
        let mut ctx = TestContext::new();
        let tlv = Tlv::ip_config(TEST_IP, TEST_NETMASK, TEST_GATEWAY);

        ctx.handle_request(SdcpOpCode::SetIpReq, 0x0002, Some(tlv));

        ctx.assert_response_sent();

        let updated_info = ctx.device_info.read_device_info().unwrap();
        assert_eq!(updated_info.ip_address, TEST_IP.to_vec());
        assert_eq!(updated_info.netmask, TEST_NETMASK.to_vec());
        assert_eq!(updated_info.gateway, TEST_GATEWAY.to_vec());
    }

    #[test]
    fn test_handle_packet_set_ip_req_failure() {
        let mut ctx = TestContext::with_failing_network();
        let tlv = Tlv::ip_config(TEST_IP, TEST_NETMASK, TEST_GATEWAY);

        ctx.handle_request(SdcpOpCode::SetIpReq, 0x0003, Some(tlv));

        ctx.assert_response_sent();

        let info = ctx.device_info.read_device_info().unwrap();
        assert_eq!(
            info.ip_address,
            vec![192, 168, 1, 100],
            "Device info should not change on failure"
        );
    }

    #[test]
    fn test_handle_packet_get_ip_req() {
        let mut ctx = TestContext::new();

        ctx.handle_request(SdcpOpCode::GetIpReq, 0x0004, None);

        ctx.assert_response_sent();
    }

    #[test]
    fn test_send_response_creates_valid_frame() {
        let mut sender = MockDataLinkSender::new();
        let interface = &pnet::datalink::interfaces()[0];
        let target_mac = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99);
        let tlv = Tlv::status_report(StatusCode::NoError);

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
        let interface = &pnet::datalink::interfaces()[0];
        let target_mac = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let opcodes = [
            SdcpOpCode::DiscoverRes,
            SdcpOpCode::GetIpRes,
            SdcpOpCode::SetIpRes,
        ];

        for opcode in &opcodes {
            let mut sender = MockDataLinkSender::new();
            let tlv = Tlv::status_report(StatusCode::NoError);

            send_response(&mut sender, interface, target_mac, *opcode, 0x0001, tlv);

            assert!(
                !sender.get_sent_packets().is_empty(),
                "Packet should have been sent for opcode {opcode:?}"
            );
        }
    }

    #[test]
    fn test_device_info_persistence_across_operations() {
        let device_info = Arc::new(MockDeviceInfo::new(TEST_MAC));

        let initial = device_info.read_device_info().unwrap();
        assert_eq!(initial.vendor_id, 0x1234);

        let mut updated = initial;
        updated.ip_address = vec![10, 0, 0, 1];
        let _ = device_info.write_device_info(updated);

        let persisted = device_info.read_device_info().unwrap();
        assert_eq!(persisted.ip_address, vec![10, 0, 0, 1]);
        assert_eq!(
            persisted.vendor_id, 0x1234,
            "Other fields should remain unchanged"
        );
    }
}
