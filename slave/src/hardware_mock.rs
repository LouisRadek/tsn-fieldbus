#![allow(dead_code)]
//! Hardware Mock
//!
//! This is a mock for the hardware implementation by a manufacturer.
//! It implements a process image with simulated data and implements both
//! the `ProcessImageAccess`, `DeviceInfoAccess`, `NetworkInterfaceAccess` and `TemperaturSensorAccess` traits.
//!
//! There are 3 different mocks combined:
//! - Tests: Simple mock for tests and integration tests
//! - Demo hardware Mock:
//!     - Temperatur Sensor
//!     - Valve Sensor

use common::{
    demo_runtime::configure_interface_ipv4,
    hardware_abstraction::{
        DeviceInfoAccess, NetworkInterfaceAccess, ProcessImageAccess, TemperatureSensorAccess,
    },
    l2_utils::bit_len_to_byte_len,
    slave_api::{DataType, DeviceInfo, Direction, IpSource, Position, ProcessVariable, StatusCode},
};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DummyHardwareRole {
    Tests,
    TemperatureSensor,
    ValveController,
}

/// Mock thread-safe hardware implementation for testing.
/// Simulates:
/// - 1 Input: Status LED (BOOL, Offset 2, Bit 0)
/// - 1 Output: Temperature Sensor (INT16, Offset 0)
/// - Device Information: MAC address, IP address, vendor ID, device ID, and serial number, firmware version, capabilities
pub struct DummyHardware {
    input_image: Arc<RwLock<Vec<u8>>>,
    output_image: Arc<RwLock<Vec<u8>>>,
    device_info: Arc<RwLock<DeviceInfo>>,
    role: DummyHardwareRole,
    interface_name: Option<String>,
}

impl DummyHardware {
    #[allow(clippy::new_without_default)]
    /// Create an instance of DummyHardware
    ///
    /// Initialize memory with zeros.
    /// Input: 1 byte (BOOL).
    /// Output: 2 bytes (INT16).
    ///
    /// Device Info: Initialize with dummy data
    pub fn new() -> Self {
        Self {
            input_image: Arc::new(RwLock::new(vec![0; 1])),
            output_image: Arc::new(RwLock::new(vec![0; 2])),
            device_info: Arc::new(RwLock::new(DeviceInfo {
                mac_address: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
                ip_address: vec![0, 0, 0, 0],
                ip_source: IpSource::Unspecified.into(),
                netmask: vec![255, 255, 255, 0],
                gateway: vec![0, 0, 0, 0],
                vendor_id: 42,
                device_id: 42,
                serial_number: 0x12345678,
                firmware_version: 1,
                capabilities: 0,
            })),
            role: DummyHardwareRole::Tests,
            interface_name: None,
        }
    }

    pub fn new_temperature_sensor(interface_name: String, mac_address: [u8; 6]) -> Self {
        Self {
            input_image: Arc::new(RwLock::new(vec![])),
            output_image: Arc::new(RwLock::new(vec![0; 2])),
            device_info: Arc::new(RwLock::new(DeviceInfo {
                mac_address: mac_address.to_vec(),
                ip_address: vec![0, 0, 0, 0],
                ip_source: IpSource::Unspecified.into(),
                netmask: vec![255, 255, 255, 0],
                gateway: vec![0, 0, 0, 0],
                vendor_id: 42,
                device_id: 1,
                serial_number: 0x1000_0001,
                firmware_version: 1,
                capabilities: 0,
            })),
            role: DummyHardwareRole::TemperatureSensor,
            interface_name: Some(interface_name),
        }
    }

    pub fn new_valve_controller(interface_name: String, mac_address: [u8; 6]) -> Self {
        Self {
            input_image: Arc::new(RwLock::new(vec![0; 1])),
            output_image: Arc::new(RwLock::new(vec![])),
            device_info: Arc::new(RwLock::new(DeviceInfo {
                mac_address: mac_address.to_vec(),
                ip_address: vec![0, 0, 0, 0],
                ip_source: IpSource::Unspecified.into(),
                netmask: vec![255, 255, 255, 0],
                gateway: vec![0, 0, 0, 0],
                vendor_id: 42,
                device_id: 2,
                serial_number: 0x1000_0002,
                firmware_version: 1,
                capabilities: 0,
            })),
            role: DummyHardwareRole::ValveController,
            interface_name: Some(interface_name),
        }
    }

    pub fn simulate_sensor_change(&self, new_temp: i16) {
        if let Ok(mut lock) = self.output_image.write() {
            lock[0] = (new_temp >> 8) as u8;
            lock[1] = (new_temp & 0xFF) as u8;
        }
    }

    pub fn get_valve_status(&self) -> bool {
        if let Ok(lock) = self.input_image.read() {
            (lock[0] & 0x01) != 0
        } else {
            false
        }
    }
}

impl DeviceInfoAccess for DummyHardware {
    fn read_device_info(&self) -> Result<DeviceInfo, StatusCode> {
        if let Ok(lock) = self.device_info.read() {
            Ok(lock.clone())
        } else {
            Err(StatusCode::ErrHardwareAccess)
        }
    }

    fn write_device_info(&self, info: DeviceInfo) -> Result<(), StatusCode> {
        if let Ok(mut lock) = self.device_info.write() {
            *lock = info;
            Ok(())
        } else {
            Err(StatusCode::ErrHardwareAccess)
        }
    }
}

impl NetworkInterfaceAccess for DummyHardware {
    fn apply_ip_config(
        &self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
    ) -> Result<(), StatusCode> {
        let _ = gateway;
        if let Some(interface_name) = &self.interface_name {
            configure_interface_ipv4(interface_name, ip, netmask)
                .map_err(|_| StatusCode::ErrHardwareAccess)?;
        }

        Ok(())
    }
}

impl ProcessImageAccess for DummyHardware {
    fn get_layout(&self) -> Result<Vec<ProcessVariable>, StatusCode> {
        match self.role {
            DummyHardwareRole::Tests => Ok(vec![
                ProcessVariable {
                    name: "Status_LED".to_string(),
                    data_type: DataType::Bool as i32,
                    direction: Direction::Output as i32,
                    byte_offset: 2,
                    bit_offset: 0,
                    bit_len: 1,
                },
                ProcessVariable {
                    name: "Temperature".to_string(),
                    data_type: DataType::Int16 as i32,
                    direction: Direction::Input as i32,
                    byte_offset: 0,
                    bit_offset: 0,
                    bit_len: 16,
                },
            ]),
            DummyHardwareRole::TemperatureSensor => Ok(vec![ProcessVariable {
                name: "Temperature".to_string(),
                data_type: DataType::Uint16 as i32,
                direction: Direction::Output as i32,
                byte_offset: 0,
                bit_offset: 0,
                bit_len: 16,
            }]),
            DummyHardwareRole::ValveController => Ok(vec![ProcessVariable {
                name: "ValveOpen".to_string(),
                data_type: DataType::Bool as i32,
                direction: Direction::Input as i32,
                byte_offset: 0,
                bit_offset: 0,
                bit_len: 1,
            }]),
        }
    }

    fn read_outputs(&self, position: Position) -> Result<Vec<u8>, StatusCode> {
        let field_byte_len = bit_len_to_byte_len(position.bit_len);
        let span_bits = position.bit_offset.saturating_add(position.bit_len);
        let span_byte_len = bit_len_to_byte_len(span_bits);
        let offset = position.byte_offset as usize;
        let end = offset + span_byte_len;

        if let Ok(lock) = self.output_image.read() {
            if offset >= lock.len() || end > lock.len() {
                return Err(StatusCode::ErrInvalidLen);
            }

            if position.bit_offset == 0 && position.bit_len.is_multiple_of(8) {
                return Ok(lock[offset..end].to_vec());
            }

            let mut out = vec![0u8; field_byte_len];
            for i in 0..position.bit_len {
                let src_bit = position.bit_offset + i;
                let src_byte = (src_bit / 8) as usize;
                let src_mask = 1u8 << (src_bit % 8);
                let bit_set = (lock[offset + src_byte] & src_mask) != 0;

                let dst_byte = (i / 8) as usize;
                let dst_mask = 1u8 << (i % 8);
                if bit_set {
                    out[dst_byte] |= dst_mask;
                }
            }

            Ok(out)
        } else {
            Err(StatusCode::ErrHardwareAccess)
        }
    }

    fn write_inputs(&self, data: &[u8], position: Position) -> Result<(), StatusCode> {
        let field_byte_len = bit_len_to_byte_len(position.bit_len);
        let span_bits = position.bit_offset.saturating_add(position.bit_len);
        let span_byte_len = bit_len_to_byte_len(span_bits);
        let offset = position.byte_offset as usize;
        let end = offset + span_byte_len;

        if let Ok(mut lock) = self.input_image.write() {
            if offset >= lock.len() || end > lock.len() || field_byte_len != data.len() {
                return Err(StatusCode::ErrInvalidLen);
            }

            if position.bit_offset == 0 && position.bit_len.is_multiple_of(8) {
                lock[offset..end].copy_from_slice(&data[..field_byte_len]);
                return Ok(());
            }

            for i in 0..position.bit_len {
                let src_byte = (i / 8) as usize;
                let src_mask = 1u8 << (i % 8);
                let bit_set = (data[src_byte] & src_mask) != 0;

                let dst_bit = position.bit_offset + i;
                let dst_byte = (dst_bit / 8) as usize;
                let dst_mask = 1u8 << (dst_bit % 8);
                let target = &mut lock[offset + dst_byte];
                if bit_set {
                    *target |= dst_mask;
                } else {
                    *target &= !dst_mask;
                }
            }

            Ok(())
        } else {
            Err(StatusCode::ErrHardwareAccess)
        }
    }
}

impl TemperatureSensorAccess for DummyHardware {
    fn read_temperature(&self) -> Result<i16, StatusCode> {
        if let Ok(lock) = self.output_image.read() {
            let high = lock.first().copied().unwrap_or(0);
            let low = lock.get(1).copied().unwrap_or(0);
            Ok(i16::from_be_bytes([high, low]))
        } else {
            Err(StatusCode::ErrHardwareAccess)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    const EXPECTED_VENDOR_ID: u32 = 42;
    const EXPECTED_DEVICE_ID: u32 = 42;
    const EXPECTED_SERIAL: u32 = 0x12345678;
    const EXPECTED_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const EXPECTED_FIRMWARE_VERSION: u32 = 1;
    const SENSOR_POSITION: Position = Position {
        byte_offset: 0,
        bit_offset: 0,
        bit_len: 16,
    };
    const LED_POSITION: Position = Position {
        byte_offset: 0,
        bit_offset: 0,
        bit_len: 1,
    };

    fn assert_sensor_bytes(hw: &DummyHardware, expected_high: u8, expected_low: u8) {
        let outputs = hw.read_outputs(SENSOR_POSITION).unwrap();
        assert_eq!(outputs[0], expected_high, "High byte mismatch");
        assert_eq!(outputs[1], expected_low, "Low byte mismatch");
    }

    fn run_concurrent<F>(hw: Arc<DummyHardware>, thread_count: usize, task: F)
    where
        F: Fn(Arc<DummyHardware>) + Send + Sync + Clone + 'static,
    {
        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let hw_clone = Arc::clone(&hw);
                let task_clone = task.clone();
                thread::spawn(move || task_clone(hw_clone))
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_initialization() {
        let hw = DummyHardware::new();

        let outputs = hw.read_outputs(SENSOR_POSITION).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs, vec![0, 0]);
        assert!(!hw.get_valve_status());
    }

    #[test]
    fn test_device_info_initialization() {
        let hw = DummyHardware::new();
        let info = hw.read_device_info().unwrap();

        assert_eq!(info.vendor_id, EXPECTED_VENDOR_ID);
        assert_eq!(info.device_id, EXPECTED_DEVICE_ID);
        assert_eq!(info.serial_number, EXPECTED_SERIAL);
        assert_eq!(info.mac_address, EXPECTED_MAC.to_vec());
        assert_eq!(info.firmware_version, EXPECTED_FIRMWARE_VERSION);
        assert_eq!(info.capabilities, 0);
    }

    #[test]
    fn test_simulate_sensor_change() {
        let hw = DummyHardware::new();

        // Test positive temperature (1000 = 0x03E8)
        hw.simulate_sensor_change(1000);
        assert_sensor_bytes(&hw, 0x03, 0xE8);

        // Test negative temperature (two's complement)
        hw.simulate_sensor_change(-1);
        assert_sensor_bytes(&hw, 0xFF, 0xFF);

        // Test zero
        hw.simulate_sensor_change(0);
        assert_sensor_bytes(&hw, 0x00, 0x00);
    }

    #[test]
    fn test_temperature_sensor_access() {
        let hw = DummyHardware::new();

        hw.simulate_sensor_change(1234);
        assert_eq!(hw.read_temperature().unwrap(), 1234);

        hw.simulate_sensor_change(-10);
        assert_eq!(hw.read_temperature().unwrap(), -10);
    }

    #[test]
    fn test_boundary_temperatures() {
        let hw = DummyHardware::new();

        hw.simulate_sensor_change(i16::MAX);
        assert_sensor_bytes(&hw, 0x7F, 0xFF);

        hw.simulate_sensor_change(i16::MIN);
        assert_sensor_bytes(&hw, 0x80, 0x00);
    }

    #[test]
    fn test_write_outputs_single_byte() {
        let hw = DummyHardware::new();
        hw.write_inputs(&[0x01], LED_POSITION).unwrap();
        assert!(hw.get_valve_status());

        hw.write_inputs(&[0x00], LED_POSITION).unwrap();
        assert!(!hw.get_valve_status());
    }

    #[test]
    fn test_write_outputs_multiple_bits() {
        let hw = DummyHardware::new();
        hw.write_inputs(&[0x01], LED_POSITION).unwrap();
        assert!(hw.get_valve_status());

        // Bit 1 set, bit 0 clear
        hw.write_inputs(&[0x00], LED_POSITION).unwrap();
        assert!(!hw.get_valve_status());

        // All bits set except bit 0
        hw.write_inputs(&[0x00], LED_POSITION).unwrap();
        assert!(!hw.get_valve_status());
    }

    #[test]
    fn test_write_outputs_oversized_buffer() {
        let hw = DummyHardware::new();
        let result = hw.write_inputs(&[0x01, 0xFF, 0xAA, 0xBB], LED_POSITION);
        assert_eq!(result, Err(StatusCode::ErrInvalidLen));
        assert!(!hw.get_valve_status());
    }

    #[test]
    fn test_write_outputs_empty_buffer() {
        let hw = DummyHardware::new();
        let result = hw.write_inputs(&[], LED_POSITION);
        assert_eq!(result, Err(StatusCode::ErrInvalidLen));
        assert!(!hw.get_valve_status());
    }

    #[test]
    fn test_get_layout() {
        let hw = DummyHardware::new();
        let layout = hw.get_layout().unwrap();

        assert_eq!(layout.len(), 2);

        let led = &layout[0];
        assert_eq!(led.name, "Status_LED");
        assert_eq!(led.byte_offset, 2);
        assert_eq!(led.bit_len, 1);
        assert_eq!(led.direction, Direction::Output as i32);

        let temp = &layout[1];
        assert_eq!(temp.name, "Temperature");
        assert_eq!(temp.byte_offset, 0);
        assert_eq!(temp.bit_len, 16);
        assert_eq!(temp.direction, Direction::Input as i32);
    }

    #[test]
    fn test_sensor_and_led_independent() {
        let hw = DummyHardware::new();

        hw.simulate_sensor_change(500);
        assert_sensor_bytes(&hw, 0x01, 0xF4);
        assert!(!hw.get_valve_status());

        hw.write_inputs(&[0x01], LED_POSITION).unwrap();
        assert!(hw.get_valve_status());
        assert_sensor_bytes(&hw, 0x01, 0xF4);
    }

    #[test]
    fn test_round_trip_sensor_to_output() {
        let hw = DummyHardware::new();

        hw.simulate_sensor_change(256);
        let outputs = hw.read_outputs(SENSOR_POSITION).unwrap();
        let result = hw.write_inputs(&outputs, LED_POSITION);
        assert_eq!(result, Err(StatusCode::ErrInvalidLen));
        assert!(!hw.get_valve_status());
    }

    #[test]
    fn test_write_device_info() {
        let hw = DummyHardware::new();

        let mut new_info = hw.read_device_info().unwrap();
        new_info.ip_address = vec![192, 168, 1, 100];
        new_info.netmask = vec![255, 255, 255, 0];
        new_info.gateway = vec![192, 168, 1, 1];
        hw.write_device_info(new_info).unwrap();

        let updated = hw.read_device_info().unwrap();
        assert_eq!(updated.ip_address, vec![192, 168, 1, 100]);
        assert_eq!(updated.netmask, vec![255, 255, 255, 0]);
        assert_eq!(updated.gateway, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_concurrent_reads() {
        let hw = Arc::new(DummyHardware::new());
        hw.simulate_sensor_change(42);

        run_concurrent(hw, 5, |hw| {
            let outputs = hw.read_outputs(SENSOR_POSITION).unwrap();
            assert_eq!(outputs, vec![0x00, 0x2A]);
        });
    }

    #[test]
    fn test_concurrent_device_info_reads() {
        let hw = Arc::new(DummyHardware::new());

        run_concurrent(hw, 5, |hw| {
            let info = hw.read_device_info();
            let info = info.unwrap();
            assert_eq!(info.serial_number, EXPECTED_SERIAL);
            assert_eq!(info.mac_address, EXPECTED_MAC.to_vec());
        });
    }

    #[test]
    fn test_concurrent_device_info_write_read() {
        let hw = Arc::new(DummyHardware::new());

        // Writers
        let hw_clone = Arc::clone(&hw);
        let writers: Vec<_> = (0..3u8)
            .map(|i| {
                let hw = Arc::clone(&hw_clone);
                thread::spawn(move || {
                    let mut info = hw.read_device_info().unwrap();
                    info.ip_address = vec![10, 0, 0, i];
                    hw.write_device_info(info).unwrap();
                })
            })
            .collect();

        // Readers
        run_concurrent(hw, 3, |hw| {
            let info = hw.read_device_info().unwrap();
            assert_eq!(info.ip_address.len(), 4);
        });

        for handle in writers {
            handle.join().unwrap();
        }
    }
}
