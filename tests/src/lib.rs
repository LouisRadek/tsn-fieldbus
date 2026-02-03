//! Integration Tests for TSN Fieldbus
//!
//! This crate provides integration tests that verify the interaction between master and slave components.
//!
//! # Architecture
//!
//! The tests use a mock network layer that simulates Ethernet frame
//! transmission between master and slave without requiring actual
//! network interfaces. This allows:
//! - Running tests without root privileges
//! - Deterministic, reproducible test execution
//! - Testing error conditions and edge cases
//!
//! # Mock Network Design
//!
//! The MockNetwork struct creates a bidirectional communication channel:
//!
//! ```text
//!  ┌────────────┐                        ┌────────────┐
//!  │   Master   │                        │   Slave    │
//!  │            │                        │            │
//!  │ Sender ────┼──► slave_inbox ───────►│ Receiver   │
//!  │            │                        │            │
//!  │ Receiver ◄─┼─── master_inbox ◄──────┼── Sender   │
//!  └────────────┘                        └────────────┘
//! ```
//!
//! Frames sent by the master appear in the slave's inbox and vice versa,
//! simulating a direct Ethernet connection.

mod mock_network;

#[cfg(test)]
mod discovery_integration_tests;

#[cfg(test)]
mod slave_api_integration_tests;
