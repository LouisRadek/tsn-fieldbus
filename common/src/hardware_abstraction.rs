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

use crate::slave_api::{DeviceInfo, ProcessVariable};

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
    /// # Implementation Notes
    /// - Implementations should use interior mutability (e.g., RwLock, Mutex) to allow mutation through &self
    /// - Should handle potential hardware write failures gracefully
    /// - This method should be thread-safe
    fn write_device_info(&self, info: DeviceInfo);
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
    /// `Ok(())` on success, `Err(String)` with error description on failure
    fn apply_ip_config(
        &self,
        ip: [u8; 4],
        netmask: [u8; 4],
        gateway: [u8; 4],
    ) -> Result<(), String>;
}
