//! TSN Fieldbus Slave Library
//!
//! This crate implements the slave-side of the TSN fieldbus protocol,
//! including SDCP discovery handling, state machine management,
//! and hardware abstraction interfaces.

mod discovery;
mod hardware_abstraction;
mod hardware_mock;
mod state_machine;

// Re-export commonly used types
pub use discovery::start_discovery_listener;
pub use hardware_abstraction::{DeviceInfoAccess, NetworkInterfaceAccess, ProcessImageAccess};
pub use hardware_mock::DummyHardware;
pub use state_machine::DeviceStateManager;

// Re-export handle_packet when test-utils feature is enabled
#[cfg(feature = "test-utils")]
pub use discovery::handle_packet;
