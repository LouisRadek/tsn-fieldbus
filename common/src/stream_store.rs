//! Stream configuration and security state storage with concurrent access.
//!
//! This module provides a thread-safe store for `StreamConfig` entries together
//! with per-stream sequence state used by L2 authentication.

use crate::l2_types::L2Header;
use crate::security::crypto::{calculate_hmac, verify_hmac};
use crate::security::shared_secret::load_shared_secret_from_env;
use crate::slave_api::{Direction, StatusCode, StreamConfig};
use log::warn;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
struct StreamEntry {
    stream_config: StreamConfig,
    sequence_number: u64,
}

#[derive(Clone)]
pub struct StreamStore {
    shared_secret: [u8; 32],
    streams: Arc<RwLock<HashMap<u16, StreamEntry>>>,
}

impl StreamStore {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            shared_secret,
            streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a stream store from `SHARED_SLAVE_KEY` hex environment value.
    pub fn from_env() -> Result<Self, String> {
        let shared_secret = load_shared_secret_from_env()?;
        Ok(Self::new(shared_secret))
    }

    pub fn reset(&self) {
        let mut stream_guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stream_guard.clear();
    }

    pub fn add_stream_config(&self, stream_config: StreamConfig) -> Result<(), StatusCode> {
        let stream_id = stream_id_as_u16(stream_config.stream_id)?;
        let mut stream_guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if stream_guard.contains_key(&stream_id) {
            return Err(StatusCode::ErrParamInvalid);
        }

        stream_guard.insert(
            stream_id,
            StreamEntry {
                sequence_number: initial_sequence_number(stream_config.direction)?,
                stream_config,
            },
        );

        Ok(())
    }

    pub fn add_stream_configs(
        &self,
        stream_configurations: Vec<StreamConfig>,
    ) -> Result<(), StatusCode> {
        let mut seen_stream_ids = HashSet::new();
        for stream_configuration in &stream_configurations {
            let stream_id = stream_id_as_u16(stream_configuration.stream_id)?;
            if !seen_stream_ids.insert(stream_id) {
                return Err(StatusCode::ErrParamInvalid);
            }
            initial_sequence_number(stream_configuration.direction)?;
        }

        let mut stream_guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for stream_configuration in stream_configurations {
            let stream_id = stream_id_as_u16(stream_configuration.stream_id)?;
            if stream_guard.contains_key(&stream_id) {
                return Err(StatusCode::ErrParamInvalid);
            }

            stream_guard.insert(
                stream_id,
                StreamEntry {
                    sequence_number: initial_sequence_number(stream_configuration.direction)?,
                    stream_config: stream_configuration,
                },
            );
        }

        Ok(())
    }

    pub fn get_stream_config(&self, stream_id: u16) -> Option<StreamConfig> {
        let stream_guard = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stream_guard
            .get(&stream_id)
            .map(|entry| entry.stream_config.clone())
    }

    pub fn get_streams_by_direction(&self, direction: Direction) -> Vec<StreamConfig> {
        let stream_guard = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        stream_guard
            .values()
            .filter(|stream| stream.stream_config.direction == direction as i32)
            .map(|stream| stream.stream_config.clone())
            .collect()
    }

    pub fn get_all_streams(&self) -> Vec<StreamConfig> {
        let stream_guard = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        stream_guard
            .values()
            .map(|stream| stream.stream_config.clone())
            .collect()
    }

    pub fn generate_stream_tag(
        &self,
        header: &L2Header,
        payload: &[u8],
    ) -> Result<(u64, [u8; 32]), StatusCode> {
        let stream_id = { header.stream_id };
        let mut stream_guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let Some(stream_entry) = stream_guard.get_mut(&stream_id) else {
            return Err(StatusCode::ErrStreamIdUnknown);
        };

        let sequence_number = stream_entry.sequence_number;
        let sequence_bytes = sequence_number.to_be_bytes();
        let header_bytes = serialize_l2_header(header);

        let tag = calculate_hmac(
            &self.shared_secret,
            &[&header_bytes, payload, &sequence_bytes],
        );

        stream_entry.sequence_number = stream_entry.sequence_number.saturating_add(1);
        Ok((sequence_number, tag))
    }

    pub fn validate_stream_tag(
        &self,
        header: &L2Header,
        payload: &[u8],
        received_sequence_number: u64,
        received_auth_tag: &[u8; 32],
    ) -> Result<bool, StatusCode> {
        let stream_id = { header.stream_id };
        let mut stream_guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let Some(stream_entry) = stream_guard.get_mut(&stream_id) else {
            return Err(StatusCode::ErrStreamIdUnknown);
        };

        if received_sequence_number <= stream_entry.sequence_number {
            warn!(
                "Invalid stream sequence number stream_id={} received={} expected_greater_than={}",
                stream_id, received_sequence_number, stream_entry.sequence_number
            );
            return Ok(false);
        }

        let header_bytes = serialize_l2_header(header);
        let sequence_bytes = received_sequence_number.to_be_bytes();
        let valid = verify_hmac(
            &self.shared_secret,
            &[&header_bytes, payload, &sequence_bytes],
            received_auth_tag,
        );

        if valid {
            stream_entry.sequence_number = received_sequence_number;
        }

        Ok(valid)
    }
}

fn serialize_l2_header(header: &L2Header) -> [u8; 7] {
    [
        header.version,
        (header.stream_id >> 8) as u8,
        header.stream_id as u8,
        (header.cycle_counter >> 8) as u8,
        header.cycle_counter as u8,
        header.status,
        header.flags,
    ]
}

fn initial_sequence_number(direction: i32) -> Result<u64, StatusCode> {
    let direction = Direction::try_from(direction).map_err(|_| StatusCode::ErrParamInvalid)?;
    Ok(match direction {
        Direction::Output => 1,
        Direction::Input => 0,
    })
}

fn stream_id_as_u16(stream_id: u32) -> Result<u16, StatusCode> {
    if stream_id > u16::MAX as u32 {
        return Err(StatusCode::ErrParamInvalid);
    }
    Ok(stream_id as u16)
}
