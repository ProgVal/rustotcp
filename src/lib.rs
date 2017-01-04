extern crate picotcp_sys;
extern crate libc;

use picotcp_sys::pico_stack_init;
use picotcp_sys::pico_stack_tick;

pub mod error;
pub mod device;
pub mod ipv4;
pub mod ipv4_link;
pub mod protocol;

pub use error::PicoError;
pub use device::Device;
pub use ipv4::Ipv4;
pub use ipv4_link::Ipv4Link;
pub use protocol::Protocol;

/// Must be called before other functions are used.
pub fn init() -> Result<(), ()> {
    match unsafe { pico_stack_init() } {
        0 => Ok(()),
        -1 => Err(()),
        res => panic!(format!("Unexpected result from pico_stack_init: {:?}", res)),
    }
}

pub fn tick()  {
    unsafe { pico_stack_tick() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
