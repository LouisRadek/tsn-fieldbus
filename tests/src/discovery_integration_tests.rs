//! Integration Tests for SDCP Discovery Protocol
//!
//! These tests verify the complete request-response cycle between
//! master and slave components of the discovery protocol.
//!
//! # Test Scenarios
//!
//! 1. **Discovery**: Master broadcasts `DiscoverReq`, slave responds with device info
//! 2. **Get IP Config**: Master queries slave's IP configuration
//! 3. **Set IP Config**: Master assigns new IP to slave, slave applies and confirms
//!
//! # Architecture
//!
//! Each test creates a `TestFixture` that connects master and slave through
//! in-memory queues. The fixture handles all the boilerplate setup, allowing
//! tests to focus on the actual protocol verification.

use crate::mock_network::{FrameQueue, MockNetwork, MockReceiver, MockSender};
use common::discovery_types::{ETHERTYPE_SDCP, SdcpHeader};
use common::hardware_abstraction::{DeviceInfoAccess, NetworkInterfaceAccess};
use common::slave_api::{DeviceState, IpSource, StatusCode};
use common::state_machine::DeviceStateManager;
use common::test_mocks::{MockDeviceInfo, MockNetworkInterface, create_mock_interface};
use master::DiscoveryMaster;
use pnet::datalink::{DataLinkReceiver, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use slave::handle_packet;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ============================================================================
// Test Fixture
// ============================================================================

const MASTER_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01);
const SLAVE_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

const TEST_IP: [u8; 4] = [10, 0, 0, 50];
const TEST_NETMASK: [u8; 4] = [255, 255, 255, 0];
const TEST_GATEWAY: [u8; 4] = [10, 0, 0, 1];

/// Encapsulates all components needed for a single-slave integration test.
struct TestFixture {
    master: DiscoveryMaster,
    slave: SlaveContext,
}

impl TestFixture {
    fn new() -> Self {
        Self::with_slave(|tx, rx| SlaveContext::new(SLAVE_MAC, tx, rx))
    }

    fn with_slave_ip(ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> Self {
        Self::with_slave(|tx, rx| SlaveContext::with_ip(SLAVE_MAC, ip, netmask, gateway, tx, rx))
    }

    fn with_failing_slave() -> Self {
        Self::with_slave(|tx, rx| SlaveContext::with_failing_network(SLAVE_MAC, tx, rx))
    }

    fn with_slave<F>(create_slave: F) -> Self
    where
        F: FnOnce(FrameQueue, FrameQueue) -> SlaveContext,
    {
        let network = MockNetwork::new();
        let (master_to_slave, slave_to_master) = network.queues();

        let master = Self::create_master(
            MASTER_MAC,
            Arc::clone(&master_to_slave),
            Arc::clone(&slave_to_master),
        );

        let slave = create_slave(slave_to_master, master_to_slave);

        Self { master, slave }
    }

    fn create_master(mac: MacAddr, tx_queue: FrameQueue, rx_queue: FrameQueue) -> DiscoveryMaster {
        let interface = create_mock_interface("master0", mac);
        let device_state_manager = DeviceStateManager::new();
        let _ = device_state_manager.set_target_state(DeviceState::DiscoverySync);
        let tx = MockSender::new(tx_queue);
        let rx = MockReceiver::new(rx_queue);
        DiscoveryMaster::new_with_mocks(interface, device_state_manager, Box::new(tx), Box::new(rx))
    }
}

struct SlaveContext {
    interface: NetworkInterface,
    device_info: Arc<dyn DeviceInfoAccess>,
    network_interface: Arc<MockNetworkInterface>,
    tx_queue: FrameQueue,
    rx_queue: FrameQueue,
}

impl SlaveContext {
    fn new(mac: MacAddr, tx_queue: FrameQueue, rx_queue: FrameQueue) -> Self {
        Self {
            interface: create_mock_interface("slave0", mac),
            device_info: Arc::new(MockDeviceInfo::new(mac)),
            network_interface: Arc::new(MockNetworkInterface::new()),
            tx_queue,
            rx_queue,
        }
    }

    fn with_ip(
        mac: MacAddr,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
        tx_queue: FrameQueue,
        rx_queue: FrameQueue,
    ) -> Self {
        Self {
            interface: create_mock_interface("slave0", mac),
            device_info: Arc::new(MockDeviceInfo::with_ip(mac, ip, netmask, gateway)),
            network_interface: Arc::new(MockNetworkInterface::new()),
            tx_queue,
            rx_queue,
        }
    }

    fn with_failing_network(mac: MacAddr, tx_queue: FrameQueue, rx_queue: FrameQueue) -> Self {
        Self {
            interface: create_mock_interface("slave0", mac),
            device_info: Arc::new(MockDeviceInfo::new(mac)),
            network_interface: Arc::new(MockNetworkInterface::failing()),
            tx_queue,
            rx_queue,
        }
    }

    fn spawn_single_frame_handler(&self) -> JoinHandle<()> {
        let interface = self.interface.clone();
        let device_info = Arc::clone(&self.device_info);
        let network_interface =
            Arc::clone(&self.network_interface) as Arc<dyn NetworkInterfaceAccess>;
        let mut tx = MockSender::new(Arc::clone(&self.tx_queue));
        let mut rx = MockReceiver::new(Arc::clone(&self.rx_queue));

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            process_single_frame(
                &mut rx,
                &mut tx,
                &interface,
                &device_info,
                &network_interface,
            );
        })
    }

    fn get_applied_configs(&self) -> Vec<([u8; 4], [u8; 4], [u8; 4])> {
        self.network_interface.get_applied_configs()
    }
}

fn process_single_frame(
    rx: &mut MockReceiver,
    tx: &mut MockSender,
    interface: &NetworkInterface,
    device_info: &Arc<dyn DeviceInfoAccess>,
    network_interface: &Arc<dyn NetworkInterfaceAccess>,
) {
    loop {
        match rx.next() {
            Ok(frame_data) => {
                if try_process_sdcp_frame(frame_data, tx, interface, device_info, network_interface)
                {
                    break;
                }
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn try_process_sdcp_frame(
    frame_data: &[u8],
    tx: &mut MockSender,
    interface: &NetworkInterface,
    device_info: &Arc<dyn DeviceInfoAccess>,
    network_interface: &Arc<dyn NetworkInterfaceAccess>,
) -> bool {
    let Some(eth_packet) = EthernetPacket::new(frame_data) else {
        return false;
    };

    if eth_packet.get_ethertype().0 != ETHERTYPE_SDCP {
        return false;
    }

    let payload = eth_packet.payload();
    let Ok(header) = SdcpHeader::read_from(payload) else {
        return false;
    };

    handle_packet(
        &header,
        payload,
        &eth_packet,
        tx,
        interface,
        device_info,
        network_interface,
    );

    true
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_discovery_full_cycle() {
    let fixture = TestFixture::new();
    let slave_handle = fixture.slave.spawn_single_frame_handler();
    let mut master = fixture.master;

    let discovered = master.discover_devices(Some(DEFAULT_TIMEOUT));
    slave_handle.join().unwrap();

    let devices = discovered.expect("Discovery should succeed");
    assert_eq!(devices.len(), 1, "Should discover exactly one device");

    let device = &devices[0];
    assert_eq!(device.mac_address, SLAVE_MAC);
    assert_eq!(device.vendor_id, 0x1234);
    assert_eq!(device.device_id, 0x5678);
    assert_eq!(device.serial_number, 0xDEADBEEF);

    assert!(master.discovered_devices().contains_key(&SLAVE_MAC));
}

#[test]
fn test_get_ip_config_full_cycle() {
    let fixture = TestFixture::with_slave_ip(TEST_IP, TEST_NETMASK, TEST_GATEWAY);
    let slave_handle = fixture.slave.spawn_single_frame_handler();
    let mut master = fixture.master;

    let ip_report = master.get_ip_config(SLAVE_MAC, Some(DEFAULT_TIMEOUT));
    slave_handle.join().unwrap();

    let report = ip_report.expect("GetIpConfig should succeed");
    assert_eq!(report.ip, TEST_IP);
    assert_eq!(report.netmask, TEST_NETMASK);
    assert_eq!(report.gateway, TEST_GATEWAY);
    assert_eq!(report.ip_source, IpSource::Manuell);
}

#[test]
fn test_set_ip_config_success() {
    let fixture = TestFixture::new();
    let slave_handle = fixture.slave.spawn_single_frame_handler();
    let mut master = fixture.master;

    let new_ip = [172, 16, 0, 100];
    let new_netmask = [255, 255, 0, 0];
    let new_gateway = [172, 16, 0, 1];

    let result = master.set_ip_config(
        SLAVE_MAC,
        new_ip,
        new_netmask,
        new_gateway,
        Some(DEFAULT_TIMEOUT),
    );
    slave_handle.join().unwrap();

    assert!(result.is_ok(), "SetIpConfig should succeed");

    let applied = fixture.slave.get_applied_configs();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0], (new_ip, new_netmask, new_gateway));

    let updated_info = fixture.slave.device_info.read_device_info().unwrap();
    assert_eq!(updated_info.ip_address, new_ip.to_vec());
    assert_eq!(updated_info.netmask, new_netmask.to_vec());
    assert_eq!(updated_info.gateway, new_gateway.to_vec());
}

#[test]
fn test_set_ip_config_failure() {
    let fixture = TestFixture::with_failing_slave();
    let slave_handle = fixture.slave.spawn_single_frame_handler();
    let mut master = fixture.master;

    let result = master.set_ip_config(
        SLAVE_MAC,
        [172, 16, 0, 100],
        [255, 255, 0, 0],
        [172, 16, 0, 1],
        Some(DEFAULT_TIMEOUT),
    );
    slave_handle.join().unwrap();

    assert_eq!(result, Err(StatusCode::ErrHardwareAccess));

    // Verify slave did NOT update device info (original IP should remain)
    let info = fixture.slave.device_info.read_device_info().unwrap();
    assert_eq!(info.ip_address, vec![192, 168, 1, 100]);
}

#[test]
fn test_multiple_devices_discovery() {
    let slave1_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x01);
    let slave2_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x02);

    let network = MockNetwork::new();
    let (master_to_slave, slave_to_master) = network.queues();

    let mut master = TestFixture::create_master(
        MASTER_MAC,
        Arc::clone(&master_to_slave),
        Arc::clone(&slave_to_master),
    );

    let slave1 = create_slave_with_device_info(
        slave1_mac,
        0x1111,
        0x1111,
        0x11111111,
        &slave_to_master,
        &master_to_slave,
    );
    let slave2 = create_slave_with_device_info(
        slave2_mac,
        0x2222,
        0x2222,
        0x22222222,
        &slave_to_master,
        &master_to_slave,
    );

    let slave_handle = spawn_multi_slave_handler(vec![slave1, slave2], master_to_slave);

    let discovered = master.discover_devices(Some(Duration::from_millis(200)));
    slave_handle.join().unwrap();

    let devices = discovered.expect("Discovery should succeed");
    assert_eq!(devices.len(), 2, "Should discover exactly two devices");

    assert!(master.discovered_devices().contains_key(&slave1_mac));
    assert!(master.discovered_devices().contains_key(&slave2_mac));

    let dev1 = master.discovered_devices().get(&slave1_mac).unwrap();
    assert_eq!(dev1.vendor_id, 0x1111);

    let dev2 = master.discovered_devices().get(&slave2_mac).unwrap();
    assert_eq!(dev2.vendor_id, 0x2222);
}

// ============================================================================
// Multi-Slave Test Helpers
// ============================================================================

struct SlaveInstance {
    interface: NetworkInterface,
    device_info: Arc<dyn DeviceInfoAccess>,
    network_interface: Arc<dyn NetworkInterfaceAccess>,
    tx: MockSender,
}

fn create_slave_with_device_info(
    mac: MacAddr,
    vendor_id: u32,
    device_id: u32,
    serial_number: u32,
    tx_queue: &FrameQueue,
    _rx_queue: &FrameQueue,
) -> SlaveInstance {
    let device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfo::new(mac));
    {
        let mut info = device_info.read_device_info().unwrap();
        info.vendor_id = vendor_id;
        info.device_id = device_id;
        info.serial_number = serial_number;
        let _ = device_info.write_device_info(info);
    }

    SlaveInstance {
        interface: create_mock_interface(&format!("slave_{:02x}", mac.5), mac),
        device_info,
        network_interface: Arc::new(MockNetworkInterface::new()),
        tx: MockSender::new(Arc::clone(tx_queue)),
    }
}

fn spawn_multi_slave_handler(
    mut slaves: Vec<SlaveInstance>,
    rx_queue: FrameQueue,
) -> JoinHandle<()> {
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));

        for _ in 0..20 {
            let frame_data = rx_queue.lock().unwrap().pop_front();

            if let Some(frame_vec) = frame_data {
                if let Some(eth_packet) = EthernetPacket::new(&frame_vec)
                    && eth_packet.get_ethertype().0 == ETHERTYPE_SDCP
                {
                    let payload = eth_packet.payload();
                    if let Ok(header) = SdcpHeader::read_from(payload) {
                        for slave in &mut slaves {
                            handle_packet(
                                &header,
                                payload,
                                &eth_packet,
                                &mut slave.tx,
                                &slave.interface,
                                &slave.device_info,
                                &slave.network_interface,
                            );
                        }
                        break;
                    }
                }
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    })
}
