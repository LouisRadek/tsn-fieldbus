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

use crate::mock_network::{
    FrameQueue, MockNetwork, MockReceiver, MockSender, create_mock_interface,
};
use common::discovery_types::{DiscoveryError, ETHERTYPE_SDCP, SdcpHeader};
use common::slave_api::{DeviceInfo, IpSource};
use common::status_codes::StatusCode;
use master::DiscoveryMaster;
use pnet::datalink::{DataLinkReceiver, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use slave::{DeviceInfoAccess, NetworkInterfaceAccess, handle_packet};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockDeviceInfo {
    info: Mutex<DeviceInfo>,
}

impl MockDeviceInfo {
    fn new(mac: MacAddr) -> Self {
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

    fn with_ip(mac: MacAddr, ip: [u8; 4], netmask: [u8; 4], gateway: [u8; 4]) -> Self {
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
    fn read_device_info(&self) -> DeviceInfo {
        self.info.lock().unwrap().clone()
    }

    fn write_device_info(&self, info: DeviceInfo) {
        *self.info.lock().unwrap() = info;
    }
}

struct MockNetworkInterface {
    #[allow(clippy::type_complexity)]
    applied_configs: Mutex<Vec<([u8; 4], [u8; 4], [u8; 4])>>,
    should_fail: bool,
}

impl MockNetworkInterface {
    fn new() -> Self {
        Self {
            applied_configs: Mutex::new(Vec::new()),
            should_fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            applied_configs: Mutex::new(Vec::new()),
            should_fail: true,
        }
    }

    fn get_applied_configs(&self) -> Vec<([u8; 4], [u8; 4], [u8; 4])> {
        self.applied_configs.lock().unwrap().clone()
    }
}

impl NetworkInterfaceAccess for MockNetworkInterface {
    fn apply_ip_config(
        &self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
    ) -> Result<(), String> {
        if self.should_fail {
            Err("Simulated network failure".to_string())
        } else {
            self.applied_configs
                .lock()
                .unwrap()
                .push((ip, netmask, gateway));
            Ok(())
        }
    }
}

// ============================================================================
// Test Fixture
// ============================================================================

const MASTER_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01);
const SLAVE_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

/// Encapsulates all components needed for a single-slave integration test.
struct TestFixture {
    master: DiscoveryMaster,
    slave: SlaveContext,
}

impl TestFixture {
    fn new() -> Self {
        Self::with_macs(MASTER_MAC, SLAVE_MAC)
    }

    fn with_macs(master_mac: MacAddr, slave_mac: MacAddr) -> Self {
        let network = MockNetwork::new();
        let (master_to_slave, slave_to_master) = network.queues();

        let master = Self::create_master(
            master_mac,
            Arc::clone(&master_to_slave),
            Arc::clone(&slave_to_master),
        );

        let slave = SlaveContext::new(
            slave_mac,
            Arc::clone(&slave_to_master),
            Arc::clone(&master_to_slave),
        );

        Self { master, slave }
    }

    fn create_master(mac: MacAddr, tx_queue: FrameQueue, rx_queue: FrameQueue) -> DiscoveryMaster {
        let interface = create_mock_interface("master0", mac);
        let tx = MockSender::new(tx_queue);
        let rx = MockReceiver::new(rx_queue);
        DiscoveryMaster::new_with_mocks(interface, Box::new(tx), Box::new(rx))
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
    let network = MockNetwork::new();
    let (master_to_slave, slave_to_master) = network.queues();

    let mut master = TestFixture::create_master(
        MASTER_MAC,
        Arc::clone(&master_to_slave),
        Arc::clone(&slave_to_master),
    );

    let expected_ip = [10, 0, 0, 50];
    let expected_netmask = [255, 255, 255, 0];
    let expected_gateway = [10, 0, 0, 1];

    let slave = SlaveContext::with_ip(
        SLAVE_MAC,
        expected_ip,
        expected_netmask,
        expected_gateway,
        slave_to_master,
        master_to_slave,
    );

    let slave_handle = slave.spawn_single_frame_handler();

    let ip_report = master.get_ip_config(SLAVE_MAC, Some(DEFAULT_TIMEOUT));
    slave_handle.join().unwrap();

    let report = ip_report.expect("GetIpConfig should succeed");
    assert_eq!(report.ip, expected_ip);
    assert_eq!(report.netmask, expected_netmask);
    assert_eq!(report.gateway, expected_gateway);
    assert_eq!(report.ip_source, IpSource::Manuell);
}

#[test]
fn test_set_ip_config_success() {
    let network = MockNetwork::new();
    let (master_to_slave, slave_to_master) = network.queues();

    let mut master = TestFixture::create_master(
        MASTER_MAC,
        Arc::clone(&master_to_slave),
        Arc::clone(&slave_to_master),
    );

    let slave = SlaveContext::new(
        SLAVE_MAC,
        Arc::clone(&slave_to_master),
        Arc::clone(&master_to_slave),
    );

    let new_ip = [172, 16, 0, 100];
    let new_netmask = [255, 255, 0, 0];
    let new_gateway = [172, 16, 0, 1];

    let slave_handle = slave.spawn_single_frame_handler();

    let result = master.set_ip_config(
        SLAVE_MAC,
        new_ip,
        new_netmask,
        new_gateway,
        Some(DEFAULT_TIMEOUT),
    );
    slave_handle.join().unwrap();

    assert!(result.is_ok(), "SetIpConfig should succeed");

    let applied = slave.get_applied_configs();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0], (new_ip, new_netmask, new_gateway));

    let updated_info = slave.device_info.read_device_info();
    assert_eq!(updated_info.ip_address, new_ip.to_vec());
    assert_eq!(updated_info.netmask, new_netmask.to_vec());
    assert_eq!(updated_info.gateway, new_gateway.to_vec());
}

#[test]
fn test_set_ip_config_failure() {
    let network = MockNetwork::new();
    let (master_to_slave, slave_to_master) = network.queues();

    let mut master = TestFixture::create_master(
        MASTER_MAC,
        Arc::clone(&master_to_slave),
        Arc::clone(&slave_to_master),
    );

    let slave = SlaveContext::with_failing_network(
        SLAVE_MAC,
        Arc::clone(&slave_to_master),
        Arc::clone(&master_to_slave),
    );

    let slave_handle = slave.spawn_single_frame_handler();

    let result = master.set_ip_config(
        SLAVE_MAC,
        [172, 16, 0, 100],
        [255, 255, 0, 0],
        [172, 16, 0, 1],
        Some(DEFAULT_TIMEOUT),
    );
    slave_handle.join().unwrap();

    match result {
        Err(DiscoveryError::DeviceError(status)) => {
            assert_eq!(status, StatusCode::OsFailure);
        }
        other => panic!("Expected DeviceError(OsFailure), got: {other:?}"),
    }

    // Verify slave did NOT update device info (original IP should remain)
    let info = slave.device_info.read_device_info();
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

    let slave1_device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfo::new(slave1_mac));
    {
        let mut info = slave1_device_info.read_device_info();
        info.vendor_id = 0x1111;
        info.device_id = 0x1111;
        info.serial_number = 0x11111111;
        slave1_device_info.write_device_info(info);
    }

    let slave2_device_info: Arc<dyn DeviceInfoAccess> = Arc::new(MockDeviceInfo::new(slave2_mac));
    {
        let mut info = slave2_device_info.read_device_info();
        info.vendor_id = 0x2222;
        info.device_id = 0x2222;
        info.serial_number = 0x22222222;
        slave2_device_info.write_device_info(info);
    }

    let slave1_interface = create_mock_interface("slave1", slave1_mac);
    let slave2_interface = create_mock_interface("slave2", slave2_mac);
    let slave_network: Arc<dyn NetworkInterfaceAccess> = Arc::new(MockNetworkInterface::new());

    let master_to_slave_clone = Arc::clone(&master_to_slave);
    let slave_to_master_clone = Arc::clone(&slave_to_master);

    let slave_handle = thread::spawn(move || {
        let mut slave1_tx = MockSender::new(Arc::clone(&slave_to_master_clone));
        let mut slave2_tx = MockSender::new(slave_to_master_clone);

        thread::sleep(Duration::from_millis(10));

        for _ in 0..20 {
            let frame_data = master_to_slave_clone.lock().unwrap().pop_front();

            if let Some(frame_vec) = frame_data {
                if let Some(eth_packet) = EthernetPacket::new(&frame_vec)
                    && eth_packet.get_ethertype().0 == ETHERTYPE_SDCP
                {
                    let payload = eth_packet.payload();
                    if let Ok(header) = SdcpHeader::read_from(payload) {
                        handle_packet(
                            &header,
                            payload,
                            &eth_packet,
                            &mut slave1_tx,
                            &slave1_interface,
                            &slave1_device_info,
                            &slave_network,
                        );
                        handle_packet(
                            &header,
                            payload,
                            &eth_packet,
                            &mut slave2_tx,
                            &slave2_interface,
                            &slave2_device_info,
                            &slave_network,
                        );
                        break;
                    }
                }
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });

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
