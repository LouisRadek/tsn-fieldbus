//! Discovery protocol authentication handler.

use crate::discovery_types::SdcpHeader;
use crate::security::crypto::{calculate_hmac, verify_hmac};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Per-device discovery security state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSecurityContext {
    pub transmitter_sequence_number: u64,
    pub last_valid_received_sequence_number: u64,
}

impl Default for DeviceSecurityContext {
    fn default() -> Self {
        Self {
            transmitter_sequence_number: 1,
            last_valid_received_sequence_number: 0,
        }
    }
}

#[derive(Clone)]
pub struct DiscoveryAuthHandler {
    shared_secret: [u8; 32],
    devices: Arc<RwLock<HashMap<MacAddr, DeviceSecurityContext>>>,
}

impl DiscoveryAuthHandler {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            shared_secret,
            devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_new_device(&self, device_mac: MacAddr) {
        let mut devices = self
            .devices
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        devices.entry(device_mac).or_default();
    }

    /// Returns `true` when a security context exists for the device.
    pub fn has_device(&self, device_mac: MacAddr) -> bool {
        let devices = self
            .devices
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        devices.contains_key(&device_mac)
    }

    pub fn set_last_valid_received_sequence_number(
        &self,
        device_mac: MacAddr,
        sequence_number: u64,
    ) -> bool {
        let mut devices = self
            .devices
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(context) = devices.get_mut(&device_mac) {
            context.last_valid_received_sequence_number = sequence_number;
            true
        } else {
            false
        }
    }

    pub fn create_auth_tag(
        &self,
        device_mac: MacAddr,
        header: &SdcpHeader,
        payload: &[u8],
    ) -> Option<(u64, [u8; 32])> {
        let mut devices = self
            .devices
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let context = devices.get_mut(&device_mac)?;
        let sequence_number = context.transmitter_sequence_number;
        let header_bytes = serialize_header(header);
        let sequence_bytes = sequence_number.to_be_bytes();

        let tag = calculate_hmac(
            &self.shared_secret,
            &[&header_bytes, payload, &sequence_bytes],
        );

        context.transmitter_sequence_number = context.transmitter_sequence_number.saturating_add(1);
        Some((sequence_number, tag))
    }

    pub fn validate_auth_tag(
        &self,
        device_mac: MacAddr,
        header: &SdcpHeader,
        payload: &[u8],
        received_sequence_number: u64,
        auth_tag: &[u8; 32],
    ) -> bool {
        let mut devices = self
            .devices
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let Some(context) = devices.get_mut(&device_mac) else {
            return false;
        };

        if received_sequence_number <= context.last_valid_received_sequence_number {
            return false;
        }

        let header_bytes = serialize_header(header);
        let sequence_bytes = received_sequence_number.to_be_bytes();
        let valid = verify_hmac(
            &self.shared_secret,
            &[&header_bytes, payload, &sequence_bytes],
            auth_tag,
        );

        if valid {
            context.last_valid_received_sequence_number = received_sequence_number;
        }

        valid
    }

    /// Validate a discovery response without requiring pre-existing context.
    ///
    /// This method is intended for bootstrapping newly discovered devices.
    pub fn validate_discovery_response(
        &self,
        header: &SdcpHeader,
        payload: &[u8],
        sequence_number: u64,
        auth_tag: &[u8; 32],
    ) -> bool {
        if sequence_number != 1 {
            return false;
        }

        let header_bytes = serialize_header(header);
        let sequence_bytes = sequence_number.to_be_bytes();
        verify_hmac(
            &self.shared_secret,
            &[&header_bytes, payload, &sequence_bytes],
            auth_tag,
        )
    }
}

fn serialize_header(header: &SdcpHeader) -> [u8; 5] {
    [
        header.version,
        header.op_code as u8,
        (header.transaction_id >> 8) as u8,
        header.transaction_id as u8,
        header.flags,
    ]
}
