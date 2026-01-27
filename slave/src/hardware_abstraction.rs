#![allow(dead_code)]
use common::slave_api::{DeviceInfo, ProcessVariable};

/// Trait abstracting the hardware access for process images.
///
/// The manufacturer must implement that the hardware stores its data in a process image which is a block of RAM.
/// Then the manufacturer has to implement this trait, i.e. the access to the process image,
/// and has to model the data stored in the process image via ProcessVariables.
pub trait ProcessImageAccess: Send + Sync {
    /// Returns the data layout and the available data in the process image.
    fn get_layout(&self) -> Vec<ProcessVariable>;

    /// Reads the current state of inputs, e.g. sensor data, into a byte buffer.
    fn read_inputs(&self) -> Vec<u8>;

    /// Writes data from the master to outputs, e.g. data for the movement of actuators.
    fn write_outputs(&mut self, data: &[u8]);
}

/// Trait abstracting the hardware access for device information.
///
/// The manufacturer must implement the logic for reading the device identity information
/// (MAC address, vendor ID, device ID, serial number, etc.) from hardware storage (e.g., EEPROM, firmware, etc.).
pub trait DeviceInfoAccess: Send + Sync {
    /// Reads the device information from hardware storage.
    ///
    /// Returns the device info containing:
    /// - MAC address
    /// - IP address; Default: 0.0.0.0
    /// - Netmask; Default: 255.255.255.0
    /// - Gateway; Default: 0.0.0.0
    /// - Vendor ID: Identifies the hardware manufacturer
    /// - Device ID: Identifies the specific device model
    /// - Serial number: Unique device identifier
    /// - Firmware Version: Version of the TSN Fieldbus Protocol; Default: 0x01
    /// - Capabilities: Reserved Flags of the TSN Fieldbus Protocol; Default: 0x00
    ///
    /// # Implementation Notes
    /// - Implementations should handle potential hardware read failures gracefully
    /// - The data is typically retrieved from EEPROM, flash, or configuration storage
    /// - This method should be thread-safe and idempotent
    fn read_device_info(&self) -> DeviceInfo;
}
