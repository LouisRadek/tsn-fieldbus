//! TSN Fieldbus Slave Library
//!
//! This crate implements the slave-side of the TSN fieldbus protocol,
//! including SDCP discovery handling, state machine management,
//! the management API and security mechanisms.

mod device_status;
mod discovery;
mod hardware_mock;
mod l2_handler;
mod slave_api;
mod token_store;

// Re-export commonly used types
pub use device_status::DeviceStatusStore;
pub use discovery::start_discovery_listener;
pub use hardware_mock::DummyHardware;
pub use l2_handler::{L2HandlerHandle, start_l2_handler};
pub use slave_api::start_slave_api_server;
pub use token_store::{PreSharedKey, TokenStore};

// Re-export handle_packet when test-utils feature is enabled
#[cfg(feature = "test-utils")]
pub use discovery::handle_packet;

#[cfg(feature = "test-utils")]
pub use l2_handler::start_l2_handler_with_mocks;
