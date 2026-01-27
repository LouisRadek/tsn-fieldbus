use std::{sync::Arc, thread, time::Duration};

use common::slave_api::DeviceState;
use log::info;

use crate::{
    hardware_abstraction::ProcessImageAccess, hardware_mock::DummyHardware,
    state_machine::DeviceStateManager,
};

mod discovery;
mod hardware_abstraction;
mod hardware_mock;
mod state_machine;

fn main() {
    env_logger::init();
    info!("Starting TSN Fieldbus Slave...");

    let hardware = Arc::new(DummyHardware::new());
    info!(
        "Hardware initialized with layout: {:?}",
        hardware.get_layout()
    );

    let state_manager = DeviceStateManager::new();

    thread::sleep(Duration::from_secs(1));
    state_manager
        .set_target_state(DeviceState::DiscoverySync)
        .unwrap();
    info!("Current State: {:?}", state_manager.get_state());

    thread::sleep(Duration::from_secs(1));
    state_manager.set_target_state(DeviceState::PreOp).unwrap();
    info!("Current State: {:?}", state_manager.get_state());

    thread::sleep(Duration::from_secs(1));
    state_manager.set_target_state(DeviceState::SafeOp).unwrap();
    info!("Current State: {:?}", state_manager.get_state());

    thread::sleep(Duration::from_secs(1));
    state_manager.set_target_state(DeviceState::Op).unwrap();
    info!("Current State: {:?}", state_manager.get_state());

    let hardware_clone = Arc::clone(&hardware);
    let _hw_handle = thread::spawn(move || {
        let mut temp_sim = 2000;
        loop {
            hardware_clone.simulate_sensor_change(temp_sim);
            temp_sim += 1;
            thread::sleep(Duration::from_millis(500));
        }
    });

    loop {
        thread::sleep(Duration::from_secs(1));
        let inputs = hardware.read_inputs();
        info!(
            "Current Temperatur: {:?}",
            i16::from_be_bytes([inputs[0], inputs[1]])
        );
    }
}
