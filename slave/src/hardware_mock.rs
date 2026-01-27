#![allow(dead_code)]
//! Hardware Mock
//!
//! This is a mock for the hardware implementation by a manufacturer.
//! It implements a process image with simulated data and implements both
//! the `ProcessImageAccess` and `DeviceInfoAccess` traits to provide access
//! to process variables and device information respectively.

use common::slave_api::{DataType, DeviceInfo, ProcessVariable, VariableDirection};
use std::sync::{Arc, RwLock};

use crate::hardware_abstraction::{DeviceInfoAccess, ProcessImageAccess};

/// Mock thread-safe hardware implementation for testing.
/// Simulates:
/// - 1 Input: Temperature Sensor (INT16, Offset 0)
/// - 1 Output: Status LED (BOOL, Offset 2, Bit 0)
/// - Device Information: MAC address, IP address, vendor ID, device ID, and serial number, firmware version, capabilities
pub struct DummyHardware {
    input_image: Arc<RwLock<Vec<u8>>>,
    output_image: Arc<RwLock<Vec<u8>>>,
    device_info: Arc<RwLock<DeviceInfo>>,
}

impl DummyHardware {
    /// Create an instance of DummyHardware
    ///
    /// Initialize memory with zeros.
    /// Input: 2 bytes (INT16).
    /// Output: 1 byte (BOOL).
    ///
    /// Device Info: Initialize with dummy data
    pub fn new() -> Self {
        Self {
            input_image: Arc::new(RwLock::new(vec![0; 2])),
            output_image: Arc::new(RwLock::new(vec![0; 1])),
            device_info: Arc::new(RwLock::new(DeviceInfo {
                mac_address: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ip_address: vec![0, 0, 0, 0],
                netmask: vec![255, 255, 255, 0],
                gateway: vec![0, 0, 0, 0],
                vendor_id: 42,
                device_id: 42,
                serial_number: 0x12345678,
                firmware_version: 1,
                capabilities: 0,
            })),
        }
    }

    /// Simulate physical change (e.g., temperature fluctuation).
    pub fn simulate_sensor_change(&self, new_temp: i16) {
        if let Ok(mut lock) = self.input_image.write() {
            lock[0] = (new_temp >> 8) as u8;
            lock[1] = (new_temp & 0xFF) as u8;
        }
    }

    /// Read actuator state for verification.
    pub fn get_led_status(&self) -> bool {
        if let Ok(lock) = self.output_image.read() {
            (lock[0] & 0x01) != 0
        } else {
            false
        }
    }
}

impl DeviceInfoAccess for DummyHardware {
    fn read_device_info(&self) -> DeviceInfo {
        if let Ok(lock) = self.device_info.read() {
            lock.clone()
        } else {
            // Fallback to default values if read fails
            DeviceInfo {
                mac_address: vec![0, 0, 0, 0, 0, 0],
                ip_address: vec![0, 0, 0, 0],
                netmask: vec![255, 255, 255, 0],
                gateway: vec![0, 0, 0, 0],
                vendor_id: 0,
                device_id: 0,
                serial_number: 0,
                firmware_version: 0,
                capabilities: 0,
            }
        }
    }
}

impl ProcessImageAccess for DummyHardware {
    fn get_layout(&self) -> Vec<ProcessVariable> {
        vec![
            ProcessVariable {
                name: "Temperature".to_string(),
                data_type: DataType::Int16 as i32,
                direction: VariableDirection::Input as i32,
                byte_offset: 0,
                bit_offset: 0,
                bit_len: 16,
            },
            ProcessVariable {
                name: "Status_LED".to_string(),
                data_type: DataType::Bool as i32,
                direction: VariableDirection::Output as i32,
                byte_offset: 2,
                bit_offset: 0,
                bit_len: 1,
            },
        ]
    }

    fn read_inputs(&self) -> Vec<u8> {
        if let Ok(lock) = self.input_image.read() {
            lock.clone()
        } else {
            vec![0; 2] // Fallback (should however not happen)
        }
    }

    fn write_outputs(&mut self, data: &[u8]) {
        if let Ok(mut lock) = self.output_image.write() {
            // Safety: prevent out of bounds writes
            let len = std::cmp::min(lock.len(), data.len());
            lock[..len].copy_from_slice(&data[..len]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_initialization() {
        let hw = DummyHardware::new();

        let inputs = hw.read_inputs();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs, vec![0, 0]);

        assert!(!hw.get_led_status());
    }

    #[test]
    fn test_simulate_sensor_change() {
        let hw = DummyHardware::new();

        // Test positive temperature
        hw.simulate_sensor_change(1000);
        let inputs = hw.read_inputs();
        assert_eq!(inputs[0], 0x03, "High byte of 1000 should be 0x03");
        assert_eq!(inputs[1], 0xE8, "Low byte of 1000 should be 0xE8");

        // Test negative temperature (two's complement)
        hw.simulate_sensor_change(-1);
        let inputs = hw.read_inputs();
        assert_eq!(inputs[0], 0xFF, "High byte of -1 should be 0xFF");
        assert_eq!(inputs[1], 0xFF, "Low byte of -1 should be 0xFF");

        // Test zero
        hw.simulate_sensor_change(0);
        let inputs = hw.read_inputs();
        assert_eq!(inputs, vec![0, 0]);
    }

    #[test]
    fn test_get_layout() {
        let hw = DummyHardware::new();
        let layout = hw.get_layout();

        assert_eq!(layout.len(), 2);

        // Check Temperature (Input)
        let temp = &layout[0];
        assert_eq!(temp.name, "Temperature");
        assert_eq!(temp.byte_offset, 0);
        assert_eq!(temp.bit_offset, 0);
        assert_eq!(temp.bit_len, 16);
        assert_eq!(temp.direction, 0);

        // Check Status_LED (Output)
        let led = &layout[1];
        assert_eq!(led.name, "Status_LED");
        assert_eq!(led.byte_offset, 2);
        assert_eq!(led.bit_offset, 0);
        assert_eq!(led.bit_len, 1);
        assert_eq!(led.direction, 1);
    }

    #[test]
    fn test_write_outputs_single_byte() {
        let mut hw = DummyHardware::new();

        // Write LED on
        hw.write_outputs(&[0x01]);
        assert!(hw.get_led_status());

        // Write LED off
        hw.write_outputs(&[0x00]);
        assert!(!hw.get_led_status());
    }

    #[test]
    fn test_write_outputs_multiple_bits() {
        let mut hw = DummyHardware::new();

        // Write all bits set
        hw.write_outputs(&[0xFF]);
        assert!(hw.get_led_status());

        // Write bit 1 set, bit 0 clear
        hw.write_outputs(&[0x02]);
        assert!(!hw.get_led_status());

        // Write all bits set except bit 0
        hw.write_outputs(&[0xFE]);
        assert!(!hw.get_led_status());
    }

    #[test]
    fn test_write_outputs_oversized_buffer() {
        let mut hw = DummyHardware::new();

        hw.write_outputs(&[0x01, 0xFF, 0xAA, 0xBB]);
        assert!(hw.get_led_status());
    }

    #[test]
    fn test_write_outputs_empty_buffer() {
        let mut hw = DummyHardware::new();

        hw.write_outputs(&[]);
        assert!(!hw.get_led_status());
    }

    #[test]
    fn test_sensor_and_led_independent() {
        let mut hw = DummyHardware::new();

        // Change sensor
        hw.simulate_sensor_change(500);
        assert_eq!(hw.read_inputs(), vec![0x01, 0xF4]);

        // LED should still be off
        assert!(!hw.get_led_status());

        // Change LED
        hw.write_outputs(&[0x01]);
        assert!(hw.get_led_status());

        // Sensor should still be the same
        assert_eq!(hw.read_inputs(), vec![0x01, 0xF4]);
    }

    #[test]
    fn test_boundary_temperatures() {
        let hw = DummyHardware::new();

        hw.simulate_sensor_change(i16::MAX);
        let inputs = hw.read_inputs();
        assert_eq!(inputs[0], 0x7F);
        assert_eq!(inputs[1], 0xFF);

        hw.simulate_sensor_change(i16::MIN);
        let inputs = hw.read_inputs();
        assert_eq!(inputs[0], 0x80);
        assert_eq!(inputs[1], 0x00);
    }

    #[test]
    fn test_concurrent_reads() {
        let hw = Arc::new(DummyHardware::new());
        hw.simulate_sensor_change(42);

        let mut handles = vec![];

        for _ in 0..5 {
            let hw_clone = Arc::clone(&hw);
            let handle = thread::spawn(move || {
                let inputs = hw_clone.read_inputs();
                assert_eq!(inputs[0], 0x00);
                assert_eq!(inputs[1], 0x2A);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_round_trip_sensor_to_output() {
        let mut hw = DummyHardware::new();

        hw.simulate_sensor_change(256);
        let inputs = hw.read_inputs();

        hw.write_outputs(&inputs);

        assert_eq!(inputs[0], 0x01);
        assert!(hw.get_led_status());
    }

    #[test]
    fn test_device_info_initialization() {
        let hw = DummyHardware::new();
        let info = hw.read_device_info();

        assert_eq!(info.vendor_id, 42);
        assert_eq!(info.device_id, 42);
        assert_eq!(info.serial_number, 0x12345678);
        assert_eq!(info.mac_address, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(info.firmware_version, 1);
        assert_eq!(info.capabilities, 0);
    }

    #[test]
    fn test_concurrent_device_info_reads() {
        let hw = Arc::new(DummyHardware::new());
        let mut handles = vec![];

        for _ in 0..5 {
            let hw_clone = Arc::clone(&hw);
            let handle = thread::spawn(move || {
                let info = hw_clone.read_device_info();
                assert_eq!(info.serial_number, 0x12345678);
                assert_eq!(info.mac_address, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
