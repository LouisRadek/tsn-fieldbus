use std::sync::Arc;

use common::{
    hardware_abstraction::ProcessImageAccess,
    slave_api::{Position, StatusCode},
};

#[derive(Clone)]
pub struct MasterProcessImage {
    input_image: Arc<std::sync::RwLock<Vec<u8>>>,
    output_image: Arc<std::sync::RwLock<Vec<u8>>>,
}

impl Default for MasterProcessImage {
    fn default() -> Self {
        Self::new()
    }
}

impl MasterProcessImage {
    pub fn new() -> Self {
        Self {
            input_image: Arc::new(std::sync::RwLock::new(vec![0u8; 2])),
            output_image: Arc::new(std::sync::RwLock::new(vec![0u8; 1])),
        }
    }

    pub fn read_temperature_u16(&self) -> u16 {
        let guard = self
            .input_image
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.len() < 2 {
            return 0;
        }
        u16::from_be_bytes([guard[0], guard[1]])
    }

    pub fn write_valve_state(&self, open: bool) {
        let mut guard = self
            .output_image
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_empty() {
            return;
        }
        if open {
            guard[0] |= 0x01;
        } else {
            guard[0] &= !0x01;
        }
    }
}

impl ProcessImageAccess for MasterProcessImage {
    fn get_layout(&self) -> Result<Vec<common::slave_api::ProcessVariable>, StatusCode> {
        Ok(vec![])
    }

    fn read_outputs(&self, position: Position) -> Result<Vec<u8>, StatusCode> {
        let byte_len = position.bit_len.div_ceil(8) as usize;
        let offset = position.byte_offset as usize;
        let guard = self
            .output_image
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .get(offset..offset + byte_len)
            .map(|slice| slice.to_vec())
            .ok_or(StatusCode::ErrInvalidLen)
    }

    fn write_inputs(&self, data: &[u8], position: Position) -> Result<(), StatusCode> {
        let byte_len = position.bit_len.div_ceil(8) as usize;
        if data.len() != byte_len {
            return Err(StatusCode::ErrInvalidLen);
        }

        let offset = position.byte_offset as usize;
        let mut guard = self
            .input_image
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.get(offset..offset + byte_len).is_none() {
            return Err(StatusCode::ErrInvalidLen);
        }

        guard[offset..offset + byte_len].copy_from_slice(data);
        Ok(())
    }
}
