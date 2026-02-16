//! TSN Fieldbus Master Library
//!
//! This crate implements the master-side of the TSN fieldbus protocol,
//! including SDCP discovery operations for finding, querying, and
//! configuring slave devices on the network as well as the cyclic L2 protocol.
mod discovery;
mod hardware_mock;
mod l2_handler;
mod slave_api_client;

// Re-export commonly used structs
pub use discovery::DiscoveryMaster;
pub use hardware_mock::MasterProcessImage;
pub use l2_handler::{L2HandlerHandle, start_l2_handler};
pub use slave_api_client::SlaveApiClient;

#[cfg(feature = "test-utils")]
pub use l2_handler::start_l2_handler_with_mocks;
