#![allow(dead_code)]
use common::slave_api::ProcessVariable;

/// Trait abstracting the hardware acess.
///
/// The manufacturer must implement that the hardware stores its data in a process image which is a block of RAM.
/// Then the manufacturer has to implement this trait, i.e. the access to the process image, and has to model the data stored in the process image via ProcessVariables.
pub trait ProcessImageAccess: Send + Sync {
    /// Returns the data layout and the available data in the process image.
    fn get_layout(&self) -> Vec<ProcessVariable>;

    /// Reads the current state of inputs, e.g. sensor data, into a byte buffer.
    fn read_inputs(&self) -> Vec<u8>;

    /// Writes data from the master to outputs, e.g. data for the movement of actuators.
    fn write_outputs(&mut self, data: &[u8]);
}
