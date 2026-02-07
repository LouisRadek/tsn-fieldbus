//! Stream configuration storage with concurrent access.
//!
//! This module provides a thread-safe store for `StreamConfig` entries which
//! can be used by the master and slave L2 protocol handlers.

use crate::slave_api::{Direction, StatusCode, StreamConfig};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct StreamStore {
    streams: Arc<RwLock<HashMap<u16, StreamConfig>>>,
}

impl StreamStore {
    pub fn new() -> Self {
        Self {
            streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn reset(&self) {
        let mut guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
    }

    pub fn add_stream_config(&self, stream: StreamConfig) -> Result<(), StatusCode> {
        let stream_id = stream_id_as_u16(stream.stream_id)?;
        let mut guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if guard.contains_key(&stream_id) {
            return Err(StatusCode::ErrParamInvalid);
        }

        guard.insert(stream_id, stream);
        Ok(())
    }

    pub fn add_stream_configs(&self, streams: Vec<StreamConfig>) -> Result<(), StatusCode> {
        let mut seen_stream_ids = HashSet::new();
        for stream in &streams {
            let stream_id = stream_id_as_u16(stream.stream_id)?;
            if !seen_stream_ids.insert(stream_id) {
                return Err(StatusCode::ErrParamInvalid);
            }
        }

        let mut guard = self
            .streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stream in streams {
            let stream_id = stream_id_as_u16(stream.stream_id)?;
            if guard.contains_key(&stream_id) {
                return Err(StatusCode::ErrParamInvalid);
            }
            guard.insert(stream_id, stream);
        }
        Ok(())
    }

    pub fn get_stream_config(&self, stream_id: u16) -> Option<StreamConfig> {
        let guard = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(&stream_id).cloned()
    }

    pub fn get_streams_by_direction(&self, direction: Direction) -> Vec<StreamConfig> {
        let guard = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .values()
            .filter(|stream| stream.direction == direction as i32)
            .cloned()
            .collect()
    }

    pub fn get_all_streams(&self) -> Vec<StreamConfig> {
        let guard = self
            .streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.values().cloned().collect()
    }
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

    #[test]
    fn test_add_and_get_stream() {
        let store = StreamStore::new();
        store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();

        let stream = store.get_stream_config(1).expect("stream not found");
        assert_eq!(stream.stream_id, 1);
    }

    #[test]
    fn test_duplicate_stream_rejected() {
        let store = StreamStore::new();
        store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();

        let result = store.add_stream_config(build_stream(1, Direction::Output));
        assert_eq!(result, Err(StatusCode::ErrParamInvalid));
    }

    #[test]
    fn test_add_multiple_streams() {
        let store = StreamStore::new();
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
        let store = StreamStore::new();
        store
            .add_stream_config(build_stream(1, Direction::Input))
            .unwrap();
        store.reset();
        assert!(store.get_all_streams().is_empty());
    }
}
