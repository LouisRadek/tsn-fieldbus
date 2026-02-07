use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::stream_store::StreamStore;
use common::{hardware_abstraction::ProcessImageAccess, slave_api::DeviceState};
use log::{debug, info};
use slave::{
    DeviceStateManager, DeviceStatusStore, DummyHardware, TokenStore, start_slave_api_server,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting TSN Fieldbus Slave...");

    let hardware = Arc::new(DummyHardware::new());
    info!(
        "Hardware initialized with layout: {:?}",
        hardware.get_layout()
    );

    let state_manager = DeviceStateManager::new();
    state_manager
        .set_target_state(DeviceState::DiscoverySync)
        .unwrap();
    state_manager.set_target_state(DeviceState::PreOp).unwrap();
    state_manager.set_target_state(DeviceState::SafeOp).unwrap();
    state_manager.set_target_state(DeviceState::Op).unwrap();

    let api_address: SocketAddr = "0.0.0.0:50051".parse()?;
    let api_device_info = Arc::clone(&hardware);
    let api_process_image = Arc::clone(&hardware);
    let api_state_manager = state_manager.clone();

    let status_store = DeviceStatusStore::new();
    status_store.spawn_background_tasks(hardware.clone());

    let token_store = TokenStore::from_env()?;
    let stream_store = StreamStore::new();

    tokio::spawn(async move {
        if let Err(error) = start_slave_api_server(
            api_address,
            api_device_info,
            api_process_image,
            api_state_manager,
            status_store,
            token_store,
            stream_store,
        )
        .await
        {
            debug!("Slave API server terminated: {error}");
        }
    });

    let hardware_clone = Arc::clone(&hardware);
    tokio::spawn(async move {
        let mut temp_sim = 2000;
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            hardware_clone.simulate_sensor_change(temp_sim);
            temp_sim += 1;
        }
    });

    let mut log_interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        log_interval.tick().await;
        let position = common::slave_api::Position {
            byte_offset: 0,
            bit_offset: 0,
            bit_len: 16,
        };
        let inputs = hardware.read_outputs(position).unwrap_or_default();
        if inputs.len() >= 2 {
            info!(
                "Current Temperatur: {:?}",
                i16::from_be_bytes([inputs[0], inputs[1]])
            );
        }
    }
}
