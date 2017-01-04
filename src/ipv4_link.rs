use picotcp_sys::pico_ipv4_link;
use picotcp_sys::pico_ipv4_nat_enable;
use picotcp_sys::pico_ipv4_nat_disable;

use error::{PicoError, get_res};

#[derive(Debug, Copy, Clone)]
pub struct Ipv4Link(*mut pico_ipv4_link);

impl Ipv4Link {
    /// `pico_ipv4_nat_enable`
    ///
    /// TODO: add example/test
    pub fn nat_enable(&mut self) -> Result<(), PicoError> {
        get_res(unsafe { pico_ipv4_nat_enable(self.0) }).map(|_res| ())
    }

    /// `pico_ipv4_nat_disable`
    ///
    /// TODO: add example/test
    pub fn nat_disable() {
        unsafe { pico_ipv4_nat_disable() };
    }
}
