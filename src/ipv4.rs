extern crate libc;

use std::fmt;
use std::ffi::CString;

use picotcp_sys::pico_ip4;
use picotcp_sys::pico_ipv4_to_string;
use picotcp_sys::pico_string_to_ipv4;
use picotcp_sys::pico_ipv4_valid_netmask;
use picotcp_sys::pico_ipv4_is_unicast;
use picotcp_sys::pico_ipv4_source_find;
use picotcp_sys::pico_ipv4_port_forward;

use error::{PicoError, get_res, get_res_ptr};
use protocol::Protocol;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Ipv4(pub u32);

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ipv4::from_string({:?})", self.to_string())
    }
}

impl Into<pico_ip4> for Ipv4 {
    fn into(self) -> pico_ip4 {
        pico_ip4 { addr: self.0 }
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
    /// # use rustotcp::Ipv4;
    /// assert_eq!(Ipv4(u32::from_be(0xC0A80101)).to_string(), "192.168.1.1");
    /// ```
    pub fn to_string(self: Ipv4) -> String {
        self.to_cstring().into_string().unwrap()
    }

    fn from_cstring(ipstr: CString) -> Result<Ipv4, ()> {
        let mut ip = 0u32;
        let res = unsafe { pico_string_to_ipv4(ipstr.as_ptr(), &mut ip as *mut u32) };
        match get_res(res) {
            Ok(_) => Ok(Ipv4(ip)),
            Err(PicoError::InvalidArgument) => Err(()),
            Err(res) => panic!(format!("Unexpected error from pico_string_to_ipv4: {:?}", res)),
        }
    }

    /// `pico_string_to_ipv4`
    ///
    /// ```
    /// # use rustotcp::Ipv4;
    /// assert_eq!(Ipv4::from_string("192.168.1.1"), Ok(Ipv4(u32::from_be(0xC0A80101))));
    /// assert_eq!(Ipv4::from_string("192.168.1.259"), Ok(Ipv4(u32::from_be(0xC0A80103)))); // https://github.com/tass-belgium/picotcp/issues/453
    /// ```
    pub fn from_string(s: &str) -> Result<Ipv4, ()> {
        Ipv4::from_cstring(CString::new(s).unwrap())
    }

    /// `pico_ipv4_valid_netmask`
    ///
    /// Returns the netmask in CIDR notation if it is valid.
    ///
    /// ```
    /// # use rustotcp::Ipv4;
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
            Err(PicoError::InvalidArgument) => Err(()),
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_valid_netmask: {:?}", res)),
        }
    }

    /// `pico_ipv4_is_unicast`
    ///
    /// Returns whether this is a unicast address
    ///
    /// TODO: improve test/example
    ///
    /// ```
    /// # use rustotcp::Ipv4;
    /// assert_eq!(Ipv4::from_string("10.10.10.0").unwrap().is_unicast(), true);
    /// ```
    pub fn is_unicast(self) -> bool {
        match get_res(unsafe { pico_ipv4_is_unicast(self.0) }) {
            Ok(0) => false,
            Ok(1) => true,
            res => panic!(format!("Unexpected result from pico_ipv4_is_unicast: {:?}", res)),
        }
    }

    /// `pico_ipv4_source_find`
    ///
    /// Returns the source IP for the link associated to this IPv4 address
    /// if the address is reachable.
    ///
    /// TODO: add test/example of working case
    ///
    /// ```
    /// # use rustotcp::Ipv4;
    /// assert_eq!(Ipv4::from_string("10.10.10.0").unwrap().find_source(), None);
    /// ```
    pub fn find_source(self) -> Option<Ipv4> {
        match get_res_ptr(unsafe { pico_ipv4_source_find(&self.into() as *const _) }) {
            Ok(source_ptr) => {
                let source = unsafe { *source_ptr }.addr;
                unsafe { libc::free(source_ptr as *mut _) };
                Some(Ipv4(source))
            }
            Err(PicoError::HostIsUnreachable) => None,
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_source_find: {:?}", res)),
        }
    }
}

/// `pico_ipv4_port_forward(..., 1)`
///
/// ```
/// # use rustotcp::ipv4::port_forward_add;
/// use rustotcp::{Ipv4, Device, Protocol, PicoError};
/// rustotcp::init().unwrap();
/// let mut eth0 = Device::new("eth0", None);
/// let mut tun0 = Device::new("tun0", None);
/// let addr_eth = Ipv4::from_string("192.168.1.1").unwrap();
/// let addr_tun = Ipv4::from_string("10.0.0.0").unwrap();
/// eth0.ipv4_link_add(addr_eth, Ipv4::from_string("255.255.255.0").unwrap()).unwrap();
/// tun0.ipv4_link_add(addr_tun, Ipv4::from_string("255.0.0.0").unwrap()).unwrap();
///
/// port_forward_add(addr_eth, 80, addr_tun, 8080, Protocol::Tcp).unwrap();
/// assert_eq!(port_forward_add(addr_eth, 80, addr_tun, 8080, Protocol::Tcp), Err(PicoError::NotSuccessfulTryAgain));
/// ```
pub fn port_forward_add(pub_addr: Ipv4, pub_port: u16, priv_addr: Ipv4, priv_port: u16, proto: Protocol) -> Result<(), PicoError> {
    match proto {
        Protocol::Icmp4 | Protocol::Tcp | Protocol::Udp => {},
        _ => return Err(PicoError::InvalidArgument),
    }
    match get_res(unsafe { pico_ipv4_port_forward(pub_addr.into(), pub_port, priv_addr.into(), priv_port, proto.into(), 1) }) {
        Ok(_) => Ok(()),
        Err(e @ PicoError::NotEnoughMemory) | Err(e @ PicoError::NotSuccessfulTryAgain) => Err(e),
        Err(res) => panic!(format!("Unexpected error from pico_ipv4_port_forward: {:?}", res)),
    }
}

/// `pico_ipv4_port_forward(..., 0)`
///
/// ```
/// # use rustotcp::ipv4::{port_forward_add, port_forward_del};
/// use rustotcp::{Ipv4, Device, Protocol};
/// rustotcp::init().unwrap();
/// let mut eth0 = Device::new("eth0", None);
/// let mut tun0 = Device::new("tun0", None);
/// let addr_eth = Ipv4::from_string("192.168.1.1").unwrap();
/// let addr_tun = Ipv4::from_string("10.0.0.0").unwrap();
/// eth0.ipv4_link_add(addr_eth, Ipv4::from_string("255.255.255.0").unwrap()).unwrap();
/// tun0.ipv4_link_add(addr_tun, Ipv4::from_string("255.0.0.0").unwrap()).unwrap();
///
/// port_forward_add(addr_eth, 80, addr_tun, 8080, Protocol::Tcp).unwrap();
/// port_forward_del(addr_eth, 80, addr_tun, 8080, Protocol::Tcp).unwrap();
/// ```
pub fn port_forward_del(pub_addr: Ipv4, pub_port: u16, priv_addr: Ipv4, priv_port: u16, proto: Protocol) -> Result<(), PicoError> {
    match proto {
        Protocol::Icmp4 | Protocol::Tcp | Protocol::Udp => {},
        _ => return Err(PicoError::InvalidArgument),
    }
    match get_res(unsafe { pico_ipv4_port_forward(pub_addr.into(), pub_port, priv_addr.into(), priv_port, proto.into(), 0) }) {
        Ok(_) => Ok(()),
        Err(e @ PicoError::NotEnoughMemory) | Err(e @ PicoError::NotSuccessfulTryAgain) => Err(e),
        Err(res) => panic!(format!("Unexpected error from pico_ipv4_port_forward: {:?}", res)),
    }
}
