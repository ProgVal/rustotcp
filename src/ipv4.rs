use std::fmt;
use std::ffi::CString;
use std::os::raw::c_char;

use picotcp_sys::pico_ipv4_to_string;
use picotcp_sys::pico_string_to_ipv4;
use picotcp_sys::pico_ipv4_valid_netmask;

use error::get_res;
use error::PicoError;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Ipv4(pub u32);

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ipv4::from_string({:?})", self.to_string())
    }
}

impl Ipv4 {
    fn to_cstring(self: Ipv4) -> CString {
        let ipbuf = CString::new("255.255.255.255").unwrap().into_raw();
        match get_res(unsafe { pico_ipv4_to_string(ipbuf, self.0) }) {
            Ok(_) => unsafe { CString::from_raw(ipbuf) },
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_to_string: {:?}", res)),
        }
    }

    /// `pico_ipv4_to_string`
    ///
    /// ```
    /// # use rustotcp::ipv4::Ipv4;
    /// assert_eq!(Ipv4(u32::from_be(0xC0A80101)).to_string(), "192.168.1.1");
    /// ```
    pub fn to_string(self: Ipv4) -> String {
        self.to_cstring().into_string().unwrap()
    }

    fn from_cstring(s: CString) -> Result<Ipv4, ()> {
        let ipstr = s.into_raw();
        let mut ip = 0u32;
        let res = unsafe { pico_string_to_ipv4(ipstr as *const c_char, &mut ip as *mut u32) };
        let _s = unsafe { CString::from_raw(ipstr) }; // Take back ownership
        match get_res(res) {
            Ok(_) => Ok(Ipv4(ip)),
            Err(PicoError::PICO_ERR_EINVAL) => Err(()),
            Err(res) => panic!(format!("Unexpected error from pico_string_to_ipv4: {:?}", res)),
        }
    }

    /// `pico_string_to_ipv4`
    ///
    /// ```
    /// # use rustotcp::ipv4::Ipv4;
    /// assert_eq!(Ipv4::from_string("192.168.1.1"), Ok(Ipv4(u32::from_be(0xC0A80101))));
    /// assert_eq!(Ipv4::from_string("192.168.1.259"), Ok(Ipv4(u32::from_be(0xC0A80103)))); // https://github.com/tass-belgium/picotcp/issues/453
    /// ```
    pub fn from_string(s: &str) -> Result<Ipv4, ()> {
        Ipv4::from_cstring(CString::new(s).unwrap())
    }

    /// `pico_ipv4_valid_netmask`
    /// Returns the netmask in CIDR notation if it is valid.
    ///
    /// ```
    /// # use rustotcp::ipv4::Ipv4;
    /// assert_eq!(Ipv4::from_string("255.255.255.0").unwrap().netmask(), Ok(24));
    /// assert_eq!(Ipv4::from_string("255.128.0.0").unwrap().netmask(), Ok(9));
    /// assert_eq!(Ipv4::from_string("255.0.1.0").unwrap().netmask(), Err(()));
    /// ```
    pub fn netmask(self) -> Result<u8, ()> {
        match get_res(unsafe { pico_ipv4_valid_netmask(self.0) }) {
            Ok(cidr_notation) => {
                assert!(0 <= cidr_notation);
                assert!(cidr_notation <= 32);
                Ok(cidr_notation as u8)
            },
            Err(PicoError::PICO_ERR_EINVAL) => Err(()),
            Err(res) => panic!(format!("Unexpected error from pico_string_to_ipv4: {:?}", res)),
        }
    }
}
