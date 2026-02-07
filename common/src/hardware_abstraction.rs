//! Hardware Abstraction Traits
//!
//! This module defines traits for abstracting hardware access in fieldbus devices.
//! These traits must be implemented by device manufacturers
//! to integrate their hardware with the TSN fieldbus protocol.
//!
//! # Traits
//!
//! - [`DeviceInfoAccess`]: Reading and writing device identification information
//! - [`NetworkInterfaceAccess`]: Configuring network interface settings
//! - [`ProcessImageAccess`]: Accessing process data (inputs/outputs)

use crate::slave_api::{DeviceInfo, Position, ProcessVariable, StatusCode};

/// Trait abstracting the hardware access for process images.
///
/// The manufacturer must implement that the hardware stores its data in a process image which is a block of RAM.
/// Then the manufacturer has to implement this trait, i.e. the access to the process image,
/// and has to model the data stored in the process image via ProcessVariables.
pub trait ProcessImageAccess: Send + Sync {
    /// Returns the data layout and the available data in the process image.
    fn get_layout(&self) -> Result<Vec<ProcessVariable>, StatusCode>;

    /// Reads the current state of output data of the provided position in the ProcessImage.
    /// The output data is e.g. sensor data or movement data for actuators, which then can be packaged and send to other devices acting as inputs for them.
    /// Throws an error if the position information does not exist in the ProcessImage
    fn read_outputs(&self, position: Position) -> Result<Vec<u8>, StatusCode>;

    /// Write input data, i.e. data got from other devices, e.g. data for the movement of actuators, into the ProcessImage to the provided position.
    /// Throws an error if the position information does not exist in the ProcessImage.
    fn write_inputs(&self, data: &[u8], position: Position) -> Result<(), StatusCode>;
}

/// Trait abstracting the hardware access for device information.
///
/// The manufacturer must implement the logic for reading the device identity information
/// (MAC address, vendor ID, device ID, serial number, etc.) from hardware storage (e.g., EEPROM, firmware, etc.).
pub trait DeviceInfoAccess: Send + Sync {
    /// Reads the device information from hardware storage.
    ///
    /// Returns the device info containing the following parameters or Err(StatusCode):
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
    fn read_device_info(&self) -> Result<DeviceInfo, StatusCode>;

    /// Writes the device information to hardware storage.
    ///
    /// This allows updating device info such as IP configuration that may need to be
    /// persisted or synchronized across threads. Typically used for:
    /// - Updating IP address via SDCP SetIpReq
    /// - Updating network configuration (netmask, gateway)
    /// - Other runtime configuration changes
    ///
    /// # Arguments
    /// * `info` - The new device information to store
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(StatusCode)` otherwise
    ///
    /// # Implementation Notes
    /// - Implementations should use interior mutability (e.g., RwLock, Mutex) to allow mutation through &self
    /// - Should handle potential hardware write failures gracefully
    /// - This method should be thread-safe
    fn write_device_info(&self, info: DeviceInfo) -> Result<(), StatusCode>;
}

/// Trait abstracting the network interface configuration.
///
/// The manufacturer must implement the logic for configuring network settings on the actual network interface,
/// such as applying IP addresses, netmasks, and gateways to the device's network card.
pub trait NetworkInterfaceAccess: Send + Sync {
    /// Applies IP configuration to the network interface.
    ///
    /// Configures the actual network interface with the provided IP settings.
    /// This is a hardware/system operation that may fail (e.g., permission denied, interface not available).
    ///
    /// # Arguments
    /// * `ip` - IP address as [u8; 4]
    /// * `netmask` - Network mask as [u8; 4]
    /// * `gateway` - Default gateway as [u8; 4]
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(StatusCode)` otherwise
    fn apply_ip_config(
        &self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
    ) -> Result<(), StatusCode>;
}

/// Trait for accessing a device-integrated temperature sensor.
///
/// Manufacturers should implement this trait to expose the current
/// temperature reading from device hardware.
/// The unit (°C, etc.) is left to the implementer but should be documented by the
/// manufacturer implementation so consumers can interpret values correctly.
///
/// # Returns
/// `Ok(i16)` on success, `Err(StatusCode)` otherwise
pub trait TemperatureSensorAccess: Send + Sync {
    /// Read the current temperature value from the hardware sensor.
    fn read_temperature(&self) -> Result<i16, StatusCode>;
}
