//! Integration tests for the L2 handler using a mocked network.

use crate::mock_network::MockNetwork;
use common::hardware_abstraction::ProcessImageAccess;
use common::l2_types::L2Header;
use common::slave_api::{DeviceState, Direction, Position, StatusCode, StreamConfig};
use common::state_machine::DeviceStateManager;
use common::stream_store::StreamStore;
use common::test_mocks::create_mock_interface;
use master::start_l2_handler_with_mocks as start_master_l2_handler;
use pnet::util::MacAddr;
use slave::{DeviceStatusStore, start_l2_handler_with_mocks as start_slave_l2_handler};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

const MASTER_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01);
const SLAVE_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
const TEST_SHARED_SECRET: [u8; 32] = [0x5A; 32];

struct TestProcessImage {
    input_image: RwLock<Vec<u8>>,
    output_image: RwLock<Vec<u8>>,
}

impl TestProcessImage {
    fn new(input_size: usize, output_size: usize) -> Self {
        Self {
            input_image: RwLock::new(vec![0u8; input_size]),
            output_image: RwLock::new(vec![0u8; output_size]),
        }
    }

    fn set_output(&self, data: &[u8]) {
        let mut guard = self.output_image.write().unwrap();
        guard[..data.len()].copy_from_slice(data);
    }

    fn read_input(&self) -> Vec<u8> {
        self.input_image.read().unwrap().clone()
    }
}

impl ProcessImageAccess for TestProcessImage {
    fn get_layout(&self) -> Result<Vec<common::slave_api::ProcessVariable>, StatusCode> {
        Ok(Vec::new())
    }

    fn read_outputs(&self, position: Position) -> Result<Vec<u8>, StatusCode> {
        let offset = position.byte_offset as usize;
        let len = position.bit_len.div_ceil(8) as usize;
        let guard = self.output_image.read().unwrap();
        guard
            .get(offset..offset + len)
            .map(|slice| slice.to_vec())
            .ok_or(StatusCode::ErrInvalidLen)
    }

    fn write_inputs(&self, data: &[u8], position: Position) -> Result<(), StatusCode> {
        let offset = position.byte_offset as usize;
        let len = position.bit_len.div_ceil(8) as usize;
        let mut guard = self.input_image.write().unwrap();
        if data.len() != len || guard.get_mut(offset..offset + len).is_none() {
            return Err(StatusCode::ErrInvalidLen);
        }
        guard[offset..offset + len].copy_from_slice(data);
        Ok(())
    }
}

fn build_stream(
    stream_id: u32,
    direction: Direction,
    destination: MacAddr,
    cycle_time_nano: u32,
) -> StreamConfig {
    StreamConfig {
        stream_id,
        destination_mac: destination.octets().to_vec(),
        vlan_id_pcp: 0x0001,
        cycle_time_nano,
        direction: direction as i32,
        stream_content: Some(Position {
            byte_offset: 0,
            bit_offset: 0,
            bit_len: 8,
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_l2_handler_bidirectional_streams() {
    let network = MockNetwork::new();
    let (master_tx, master_rx) = network.master_endpoints();
    let (slave_tx, slave_rx) = network.slave_endpoints();

    let master_interface = create_mock_interface("master0", MASTER_MAC);
    let slave_interface = create_mock_interface("slave0", SLAVE_MAC);

    let master_store = StreamStore::new(TEST_SHARED_SECRET);
    master_store
        .add_stream_config(build_stream(1, Direction::Output, SLAVE_MAC, 1_000_000))
        .unwrap();
    master_store
        .add_stream_config(build_stream(2, Direction::Input, MASTER_MAC, 1_000_000))
        .unwrap();

    let slave_store = StreamStore::new(TEST_SHARED_SECRET);
    slave_store
        .add_stream_config(build_stream(1, Direction::Input, SLAVE_MAC, 1_000_000))
        .unwrap();
    slave_store
        .add_stream_config(build_stream(2, Direction::Output, MASTER_MAC, 1_000_000))
        .unwrap();

    let master_process_image: Arc<TestProcessImage> = Arc::new(TestProcessImage::new(1, 1));
    let slave_process_image: Arc<TestProcessImage> = Arc::new(TestProcessImage::new(1, 1));
    let master_process_image_access: Arc<dyn ProcessImageAccess> =
        Arc::clone(&master_process_image) as Arc<dyn ProcessImageAccess>;
    let slave_process_image_access: Arc<dyn ProcessImageAccess> =
        Arc::clone(&slave_process_image) as Arc<dyn ProcessImageAccess>;
    master_process_image.set_output(&[0x01]);
    slave_process_image.set_output(&[0x02]);

    let master_device_state_manager = DeviceStateManager::new();
    let _ = master_device_state_manager.set_target_state(DeviceState::DiscoverySync);
    let _ = master_device_state_manager.set_target_state(DeviceState::PreOp);
    let _ = master_device_state_manager.set_target_state(DeviceState::SafeOp);
    let _ = master_device_state_manager.set_target_state(DeviceState::Op);
    let status_store = DeviceStatusStore::new();
    status_store.update_state(DeviceState::Op).await;

    let master_handle = start_master_l2_handler(
        master_interface,
        Box::new(master_tx),
        Box::new(master_rx),
        master_store,
        master_device_state_manager.clone(),
        Arc::clone(&master_process_image_access),
    )
    .expect("start master l2 handler");

    let slave_handle = start_slave_l2_handler(
        slave_interface,
        Box::new(slave_tx),
        Box::new(slave_rx),
        slave_store,
        status_store.clone(),
        Arc::clone(&slave_process_image_access),
    );

    sleep(Duration::from_millis(50)).await;
    status_store.update_state(DeviceState::Shutdown).await;
    let _ = master_device_state_manager.set_target_state(DeviceState::Shutdown);

    assert_eq!(slave_process_image.read_input()[0], 0x01);
    assert_eq!(master_process_image.read_input()[0], 0x02);

    master_handle.join();
    slave_handle.join();
}

#[test]
fn test_stream_security_unidirectional_sequence_logic() {
    let output_store = StreamStore::new(TEST_SHARED_SECRET);
    output_store
        .add_stream_config(build_stream(1, Direction::Output, SLAVE_MAC, 1_000_000))
        .unwrap();

    let output_header = L2Header::new(1, 1, StatusCode::NoError as u8);
    let payload = [0x11, 0x22];
    let (sequence_number_a, _) = output_store
        .generate_stream_tag(&output_header, &payload)
        .expect("first tag should be generated");
    let (sequence_number_b, _) = output_store
        .generate_stream_tag(&output_header, &payload)
        .expect("second tag should be generated");
    assert_eq!(sequence_number_a, 1);
    assert_eq!(sequence_number_b, 2);

    let input_sender = StreamStore::new(TEST_SHARED_SECRET);
    let input_receiver = StreamStore::new(TEST_SHARED_SECRET);
    input_sender
        .add_stream_config(build_stream(2, Direction::Output, MASTER_MAC, 1_000_000))
        .unwrap();
    input_receiver
        .add_stream_config(build_stream(2, Direction::Input, MASTER_MAC, 1_000_000))
        .unwrap();

    let input_header = L2Header::new(2, 1, StatusCode::NoError as u8);
    let (received_sequence_number, received_auth_tag) = input_sender
        .generate_stream_tag(&input_header, &payload)
        .expect("sender should generate tag");
    assert!(
        input_receiver
            .validate_stream_tag(
                &input_header,
                &payload,
                received_sequence_number,
                &received_auth_tag,
            )
            .expect("validation should succeed")
    );
}

#[test]
fn test_replay_protection_isolated_per_stream() {
    let sender_store = StreamStore::new(TEST_SHARED_SECRET);
    let receiver_store = StreamStore::new(TEST_SHARED_SECRET);

    sender_store
        .add_stream_config(build_stream(10, Direction::Output, SLAVE_MAC, 1_000_000))
        .unwrap();
    sender_store
        .add_stream_config(build_stream(11, Direction::Output, SLAVE_MAC, 1_000_000))
        .unwrap();
    receiver_store
        .add_stream_config(build_stream(10, Direction::Input, MASTER_MAC, 1_000_000))
        .unwrap();
    receiver_store
        .add_stream_config(build_stream(11, Direction::Input, MASTER_MAC, 1_000_000))
        .unwrap();

    let payload_stream_a = [0xAA, 0x01];
    let payload_stream_b = [0xBB, 0x02];
    let header_stream_a = L2Header::new(10, 1, StatusCode::NoError as u8);
    let header_stream_b = L2Header::new(11, 1, StatusCode::NoError as u8);

    let (sequence_number_stream_a, auth_tag_stream_a) = sender_store
        .generate_stream_tag(&header_stream_a, &payload_stream_a)
        .expect("stream A tag should be generated");
    let (sequence_number_stream_b, auth_tag_stream_b) = sender_store
        .generate_stream_tag(&header_stream_b, &payload_stream_b)
        .expect("stream B tag should be generated");

    assert!(
        receiver_store
            .validate_stream_tag(
                &header_stream_a,
                &payload_stream_a,
                sequence_number_stream_a,
                &auth_tag_stream_a,
            )
            .expect("stream A first frame should validate")
    );
    assert!(
        !receiver_store
            .validate_stream_tag(
                &header_stream_a,
                &payload_stream_a,
                sequence_number_stream_a,
                &auth_tag_stream_a,
            )
            .expect("stream A replay should be rejected")
    );
    assert!(
        receiver_store
            .validate_stream_tag(
                &header_stream_b,
                &payload_stream_b,
                sequence_number_stream_b,
                &auth_tag_stream_b,
            )
            .expect("stream B should still validate after stream A replay")
    );
}
