//! Stream configuration and security state storage with concurrent access.
//!
//! This module provides a thread-safe store for `StreamConfig` entries together
//! with per-stream sequence state used by L2 authentication.

use crate::l2_types::L2Header;
use crate::security::auth_footer::AUTH_TAG_SIZE;
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
    ) -> Result<(u64, [u8; AUTH_TAG_SIZE]), StatusCode> {
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
        received_auth_tag: &[u8; AUTH_TAG_SIZE],
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

#[cfg(test)]
mod tests {
    use crate::slave_api::Position;

    use super::*;

    fn build_stream(stream_id: u32, direction: Direction) -> StreamConfig {
        StreamConfig {
            stream_id,
            destination_mac: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id_pcp: 0x0001,
            cycle_time_nano: 1_000,
            direction: direction as i32,
            stream_content: Some(Position {
                byte_offset: 0,
                bit_offset: 0,
                bit_len: 16,
            }),
        }
    }

    fn build_header(stream_id: u16) -> L2Header {
        L2Header::new(stream_id, 1, 0)
    }

    #[test]
    fn test_add_and_get_stream() {
        let store = StreamStore::new([0x11; 32]);
        store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();

        let stream = store.get_stream_config(1).expect("stream not found");
        assert_eq!(stream.stream_id, 1);
    }

    #[test]
    fn test_duplicate_stream_rejected() {
        let store = StreamStore::new([0x11; 32]);
        store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();

        let result = store.add_stream_config(build_stream(1, Direction::Output));
        assert_eq!(result, Err(StatusCode::ErrParamInvalid));
    }

    #[test]
    fn test_add_multiple_streams() {
        let store = StreamStore::new([0x11; 32]);
        store
            .add_stream_configs(vec![
                build_stream(1, Direction::Input),
                build_stream(2, Direction::Output),
            ])
            .unwrap();

        let inputs = store.get_streams_by_direction(Direction::Input);
        let outputs = store.get_streams_by_direction(Direction::Output);
        assert_eq!(inputs.len(), 1);
        assert_eq!(outputs.len(), 1);
    }

    #[test]
    fn test_reset_clears_store() {
        let store = StreamStore::new([0x11; 32]);
        store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();
        store.reset();
        assert!(store.get_all_streams().is_empty());
    }

    #[test]
    fn test_generate_stream_tag_increments_output_sequence() {
        let store = StreamStore::new([0x55; 32]);
        store
            .add_stream_config(build_stream(1, Direction::Output))
            .unwrap();

        let header = build_header(1);
        let payload = [0x01, 0x02, 0x03];

        let (sequence_a, _) = store.generate_stream_tag(&header, &payload).unwrap();
        let (sequence_b, _) = store.generate_stream_tag(&header, &payload).unwrap();

        assert_eq!(sequence_a, 1);
        assert_eq!(sequence_b, 2);
    }

    #[test]
    fn test_validate_stream_tag_accepts_and_updates_sequence() {
        let secret = [0x66; 32];
        let sender_store = StreamStore::new(secret);
        let receiver_store = StreamStore::new(secret);

        sender_store
            .add_stream_config(build_stream(1, Direction::Output))
            .unwrap();
        receiver_store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();

        let header = build_header(1);
        let payload = [0xAA, 0xBB];
        let (sequence_number, auth_tag) =
            sender_store.generate_stream_tag(&header, &payload).unwrap();

        assert!(
            receiver_store
                .validate_stream_tag(&header, &payload, sequence_number, &auth_tag)
                .unwrap()
        );
    }

    #[test]
    fn test_validate_stream_tag_rejects_replay() {
        let secret = [0x77; 32];
        let sender_store = StreamStore::new(secret);
        let receiver_store = StreamStore::new(secret);

        sender_store
            .add_stream_config(build_stream(1, Direction::Output))
            .unwrap();
        receiver_store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();

        let header = build_header(1);
        let payload = [0xAA, 0xBB];
        let (sequence_number, auth_tag) =
            sender_store.generate_stream_tag(&header, &payload).unwrap();

        assert!(
            receiver_store
                .validate_stream_tag(&header, &payload, sequence_number, &auth_tag)
                .unwrap()
        );
        assert!(
            !receiver_store
                .validate_stream_tag(&header, &payload, sequence_number, &auth_tag)
                .unwrap()
        );
    }
}
