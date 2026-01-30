#![allow(dead_code)]
//! Mock Network Infrastructure for Integration Testing
//!
//! This module provides mock implementations of pnet's `DataLinkSender` and
//! `DataLinkReceiver` traits that communicate through in-memory channels
//! instead of real network interfaces.
//!
//! # Usage
//!
//! ```ignore
//! let network = MockNetwork::new();
//! let (master_tx, master_rx) = network.master_endpoints();
//! let (slave_tx, slave_rx) = network.slave_endpoints();
//!
//! // Master sends a frame
//! master_tx.send_to(&frame, None);
//!
//! // Slave receives it
//! let received = slave_rx.next().unwrap();
//! ```

use pnet::datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

/// Type alias for a thread-safe frame queue.
pub type FrameQueue = Arc<Mutex<VecDeque<Vec<u8>>>>;

fn new_frame_queue() -> FrameQueue {
    Arc::new(Mutex::new(VecDeque::new()))
}

/// Mock network that connects master and slave through in-memory queues.
///
/// This simulates a direct Ethernet connection between two endpoints
/// without requiring actual network hardware
pub struct MockNetwork {
    master_to_slave: FrameQueue,
    slave_to_master: FrameQueue,
}

impl MockNetwork {
    pub fn new() -> Self {
        Self {
            master_to_slave: new_frame_queue(),
            slave_to_master: new_frame_queue(),
        }
    }

    /// Returns the sender and receiver for the master endpoint.
    pub fn master_endpoints(&self) -> (MockSender, MockReceiver) {
        (
            MockSender::new(Arc::clone(&self.master_to_slave)),
            MockReceiver::new(Arc::clone(&self.slave_to_master)),
        )
    }

    /// Returns the sender and receiver for the slave endpoint.
    pub fn slave_endpoints(&self) -> (MockSender, MockReceiver) {
        (
            MockSender::new(Arc::clone(&self.slave_to_master)),
            MockReceiver::new(Arc::clone(&self.master_to_slave)),
        )
    }

    /// Returns direct access to frame queues for custom test scenarios.
    pub fn queues(&self) -> (FrameQueue, FrameQueue) {
        (
            Arc::clone(&self.master_to_slave),
            Arc::clone(&self.slave_to_master),
        )
    }
}

impl Default for MockNetwork {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock sender that writes frames to a shared queue.
pub struct MockSender {
    outbox: FrameQueue,
}

impl MockSender {
    pub fn new(outbox: FrameQueue) -> Self {
        Self { outbox }
    }
}

impl DataLinkSender for MockSender {
    fn send_to(
        &mut self,
        packet: &[u8],
        _dst: Option<NetworkInterface>,
    ) -> Option<Result<(), io::Error>> {
        self.outbox.lock().unwrap().push_back(packet.to_vec());
        Some(Ok(()))
    }

    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<Result<(), io::Error>> {
        Some(Ok(()))
    }
}

/// Mock receiver that reads frames from a shared queue.
pub struct MockReceiver {
    inbox: FrameQueue,
    /// Buffer to hold the current frame for lifetime management.
    /// The `next()` method returns a reference to this buffer.
    current_frame: Vec<u8>,
}

impl MockReceiver {
    pub fn new(inbox: FrameQueue) -> Self {
        Self {
            inbox,
            current_frame: Vec::new(),
        }
    }

    pub fn has_frames(&self) -> bool {
        !self.inbox.lock().unwrap().is_empty()
    }

    pub fn pending_count(&self) -> usize {
        self.inbox.lock().unwrap().len()
    }
}

impl DataLinkReceiver for MockReceiver {
    fn next(&mut self) -> Result<&[u8], io::Error> {
        if let Some(frame) = self.inbox.lock().unwrap().pop_front() {
            self.current_frame = frame;
            Ok(&self.current_frame)
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "No frames available",
            ))
        }
    }
}

/// Creates a mock `NetworkInterface` for testing.
pub fn create_mock_interface(name: &str, mac: MacAddr) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        description: format!("Mock interface {name}"),
        index: 0,
        mac: Some(mac),
        ips: vec![],
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_network_bidirectional() {
        let network = MockNetwork::new();
        let (mut master_tx, mut master_rx) = network.master_endpoints();
        let (mut slave_tx, mut slave_rx) = network.slave_endpoints();

        // Master sends to slave
        let frame1 = vec![1, 2, 3, 4];
        master_tx.send_to(&frame1, None);
        assert!(slave_rx.has_frames());
        assert_eq!(slave_rx.next().unwrap(), &frame1[..]);

        // Slave sends to master
        let frame2 = vec![5, 6, 7, 8];
        slave_tx.send_to(&frame2, None);
        assert!(master_rx.has_frames());
        assert_eq!(master_rx.next().unwrap(), &frame2[..]);
    }

    #[test]
    fn test_mock_receiver_empty() {
        let queue = new_frame_queue();
        let mut receiver = MockReceiver::new(queue);

        assert!(!receiver.has_frames());
        assert!(receiver.next().is_err());
    }

    #[test]
    fn test_mock_receiver_multiple_frames() {
        let queue = new_frame_queue();
        queue.lock().unwrap().push_back(vec![1, 2]);
        queue.lock().unwrap().push_back(vec![3, 4]);
        queue.lock().unwrap().push_back(vec![5, 6]);

        let mut receiver = MockReceiver::new(queue);
        assert_eq!(receiver.pending_count(), 3);

        assert_eq!(receiver.next().unwrap(), &[1, 2][..]);
        assert_eq!(receiver.next().unwrap(), &[3, 4][..]);
        assert_eq!(receiver.next().unwrap(), &[5, 6][..]);
        assert!(receiver.next().is_err());
    }
}
