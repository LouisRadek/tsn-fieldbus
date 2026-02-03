//! TSN Fieldbus Slave Library
//!
//! This crate implements the slave-side of the TSN fieldbus protocol,
//! including SDCP discovery handling, state machine management,
//! the management API and security mechanisms.

mod device_status;
mod discovery;
mod hardware_mock;
mod slave_api;
mod state_machine;
mod token_store;

// Re-export commonly used types
pub use device_status::DeviceStatusStore;
pub use discovery::start_discovery_listener;
pub use hardware_mock::DummyHardware;
pub use slave_api::start_slave_api_server;
pub use state_machine::DeviceStateManager;
pub use token_store::TokenStore;

// Re-export handle_packet when test-utils feature is enabled
#[cfg(feature = "test-utils")]
pub use discovery::handle_packet;
