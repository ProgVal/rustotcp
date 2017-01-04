use picotcp_sys::pico_ipv4_link;
use picotcp_sys::pico_ipv4_link_get;
use picotcp_sys::pico_ipv4_nat_enable;
use picotcp_sys::pico_ipv4_nat_disable;

use ipv4::Ipv4;
use error::{PicoError, get_res};

#[derive(Debug, Copy, Clone)]
pub struct Ipv4Link(*mut pico_ipv4_link);

impl Into<*mut pico_ipv4_link> for Ipv4Link {
    fn into(self) -> *mut pico_ipv4_link {
        self.0
    }
}

impl Ipv4Link {
    /// `pico_ipv4_link_get` (not documented upstream)
    ///
    /// Returns the link associated to the IPv4 address
    pub fn get(addr: Ipv4) -> Option<Ipv4Link> {
        let link = unsafe { pico_ipv4_link_get(&mut addr.into() as *mut _) }; // TODO: remove mutability
        if link.is_null() {
            None
        }
        else {
            Some(Ipv4Link(link))
        }
    }

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
