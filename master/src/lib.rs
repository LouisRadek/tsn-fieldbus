//! TSN Fieldbus Master Library
//!
//! This crate implements the master-side of the TSN fieldbus protocol,
//! including SDCP discovery operations for finding, querying, and
//! configuring slave devices on the network.

mod discovery;
mod slave_api_client;

// Re-export commonly used structs
pub use discovery::DiscoveryMaster;
pub use slave_api_client::SlaveApiClient;
