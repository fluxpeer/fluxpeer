mod device;

pub use device::{Device, Queue};

use crate::{configuration::Configuration as C, error::*};

/// Windows-only interface configuration.
#[derive(Copy, Clone, Default, Debug)]
pub struct Configuration {}

/// Create a TUN device with the given name.
pub fn create(configuration: &C) -> Result<Device> {
    Device::new(configuration)
}
