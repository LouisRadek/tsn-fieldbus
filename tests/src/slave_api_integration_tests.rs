//! Integration tests for the Slave API gRPC service.
//!
//! These tests spin up a real gRPC server using the slave runtime components
//! and exercise all public RPC endpoints through the master-side client.

use common::slave_api::{
    DeviceState, Direction, StatusCode, StreamConfig, StreamContent, SubscribeStatusRequest,
};
use common::stream_store::StreamStore;
use master::SlaveApiClient;
use slave::{
    DeviceStateManager, DeviceStatusStore, DummyHardware, TokenStore, start_slave_api_server,
};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tonic::Code;

const SHARED_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const SHARED_KEY_BYTES: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn init_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        unsafe { std::env::set_var("SHARED_SLAVE_KEY", SHARED_KEY_HEX) };
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

fn pick_free_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to ephemeral port");
    let addr = listener.local_addr().expect("read local addr");
    drop(listener);
    addr
}

async fn start_slave_server() -> (SocketAddr, DeviceStatusStore, tokio::task::JoinHandle<()>) {
    init_env();
    let address = pick_free_port();

    let hardware = Arc::new(DummyHardware::new());
    let device_info_access = Arc::clone(&hardware);
    let process_image_access = Arc::clone(&hardware);
    let state_manager = DeviceStateManager::new();
    let status_store = DeviceStatusStore::new();
    let token_store = TokenStore::from_env().expect("token store from env");
    let stream_store = StreamStore::new();

    let status_store_clone = status_store.clone();

    let handle = tokio::spawn(async move {
        let _ = start_slave_api_server(
            address,
            device_info_access,
            process_image_access,
            state_manager,
            status_store_clone,
            token_store,
            stream_store,
        )
        .await;
    });

    (address, status_store, handle)
}

async fn connect_client(address: SocketAddr, shared_key: Vec<u8>) -> SlaveApiClient {
    let endpoint = format!("http://{}", address);
    for _ in 0..10u8 {
        if let Ok(client) = SlaveApiClient::connect(endpoint.clone(), shared_key.clone()).await {
            return client;
        }
        sleep(Duration::from_millis(20)).await;
    }
    SlaveApiClient::connect(endpoint, shared_key)
        .await
        .expect("connect to slave api")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_slave_api_endpoints() {
    let (address, status_store, handle) = start_slave_server().await;
    let mut client = connect_client(address, SHARED_KEY_BYTES.to_vec()).await;

    let token_response = client.get_token().await.expect("get token");
    assert_eq!(token_response.status, StatusCode::NoError as i32);
    assert!(!token_response.token.is_empty());

    let status = client.get_status().await.expect("get status");
    assert_eq!(status.state, DeviceState::Init as i32);

    let set_response = client
        .set_target_state(DeviceState::DiscoverySync)
        .await
        .expect("set target state");
    assert_eq!(set_response.code, StatusCode::NoError as i32);

    let status = client.get_status().await.expect("get status");
    assert_eq!(status.state, DeviceState::DiscoverySync as i32);

    let device_info_response = client.get_device_info().await.expect("get device info");
    assert_eq!(device_info_response.code, StatusCode::NoError as i32);
    let device_info = device_info_response
        .device_info
        .expect("device info should be present");
    assert!(!device_info.mac_address.is_empty());

    let layout = client
        .get_process_data_layout()
        .await
        .expect("get process data layout");
    assert_eq!(layout.code, StatusCode::NoError as i32);
    assert!(!layout.variables.is_empty());

    status_store.update_state(DeviceState::DiscoverySync).await;
    let log_response = client.get_device_status_log(0, 10).await.expect("get log");
    assert!(log_response.total_entries >= 1);

    let reset_response = client.reset_sequence_number().await.expect("reset seq");
    assert_eq!(reset_response.code, StatusCode::ErrNotSupported as i32);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subscribe_stream_receives_updates() {
    let (address, status_store, handle) = start_slave_server().await;
    let mut client = connect_client(address, SHARED_KEY_BYTES.to_vec()).await;

    client.get_token().await.expect("get token");

    let mut stream = client
        .subscribe_to_device_status(SubscribeStatusRequest {
            min_interval_sec: None,
        })
        .await
        .expect("subscribe to status");

    status_store.update_state(DeviceState::DiscoverySync).await;

    let message = timeout(Duration::from_millis(200), stream.message())
        .await
        .expect("timeout waiting for status")
        .expect("stream error")
        .expect("expected status message");

    assert_eq!(message.state, DeviceState::DiscoverySync as i32);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_invalid_shared_key_fails_authentication() {
    let (address, _status_store, handle) = start_slave_server().await;
    let invalid_key = vec![0xFF; 32];
    let mut client = connect_client(address, invalid_key).await;

    let token_response = client.get_token().await.expect("get token");
    assert_eq!(token_response.status, StatusCode::ErrAuthFailed as i32);
    assert!(token_response.token.is_empty());

    let status = client.get_status().await;
    assert!(status.is_err());
    assert_eq!(status.err().unwrap().code(), Code::Unauthenticated);

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_configure_streams_preop_only_and_validation() {
    let (address, _status_store, handle) = start_slave_server().await;
    let mut client = connect_client(address, SHARED_KEY_BYTES.to_vec()).await;

    client.get_token().await.expect("get token");

    let response = client
        .configure_streams(vec![StreamConfig {
            stream_id: 1,
            destination_mac: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id_pcp: 0x0001,
            cycle_time_nano: 1_000_000,
            direction: Direction::Input as i32,
            stream_content: Some(StreamContent {
                byte_offset: 0,
                bit_offset: 0,
                bit_len: 16,
            }),
        }])
        .await
        .expect("configure streams");
    assert_eq!(response.code, StatusCode::ErrNotReady as i32);

    client
        .set_target_state(DeviceState::DiscoverySync)
        .await
        .expect("set discovery sync");
    client
        .set_target_state(DeviceState::PreOp)
        .await
        .expect("set pre-op");

    let response = client
        .configure_streams(vec![StreamConfig {
            stream_id: 1,
            destination_mac: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id_pcp: 0x0001,
            cycle_time_nano: 1_000_000,
            direction: Direction::Input as i32,
            stream_content: Some(StreamContent {
                byte_offset: 0,
                bit_offset: 0,
                bit_len: 16,
            }),
        }])
        .await
        .expect("configure streams");
    assert_eq!(response.code, StatusCode::NoError as i32);

    let response = client
        .configure_streams(vec![
            StreamConfig {
                stream_id: 2,
                destination_mac: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                vlan_id_pcp: 0x0001,
                cycle_time_nano: 1_000_000,
                direction: Direction::Input as i32,
                stream_content: Some(StreamContent {
                    byte_offset: 0,
                    bit_offset: 0,
                    bit_len: 16,
                }),
            },
            StreamConfig {
                stream_id: 2,
                destination_mac: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                vlan_id_pcp: 0x0001,
                cycle_time_nano: 1_000_000,
                direction: Direction::Input as i32,
                stream_content: Some(StreamContent {
                    byte_offset: 0,
                    bit_offset: 0,
                    bit_len: 16,
                }),
            },
        ])
        .await
        .expect("configure streams with duplicates");
    assert_eq!(response.code, StatusCode::ErrParamInvalid as i32);

    handle.abort();
}
