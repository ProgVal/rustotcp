extern crate libc;

use std::fmt;
use std::ptr;
use std::ffi::CString;

use picotcp_sys::pico_ip4;
use picotcp_sys::pico_ipv4_link;
use picotcp_sys::pico_ipv4_to_string;
use picotcp_sys::pico_string_to_ipv4;
use picotcp_sys::pico_ipv4_valid_netmask;
use picotcp_sys::pico_ipv4_is_unicast;
use picotcp_sys::pico_ipv4_source_find;
use picotcp_sys::pico_ipv4_port_forward;
use picotcp_sys::pico_ipv4_route_add;
use picotcp_sys::pico_ipv4_route_del;
use picotcp_sys::pico_ipv4_route_get_gateway;

use error::{PicoError, get_res, get_res_ptr, read_pico_err};
use ipv4_link::Ipv4Link;
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
        Err(e @ PicoError::NotEnoughMemory) |
        Err(e @ PicoError::NotSuccessfulTryAgain) => Err(e),
        Err(res) => panic!(format!("Unexpected error from pico_ipv4_port_forward: {:?}", res)),
    }
}

/// `pico_ipv4_route_add` for non-default routes
///
/// If both `gateway` and `link` are `None`, errors with `PicoError::InvalidArgument`.
///
/// See also: `ipv4::default_route_add`
///
/// ```
/// # use rustotcp::ipv4::{route_add};
/// use rustotcp::{init, Ipv4, Ipv4Link, Device, PicoError};
///
/// init().unwrap();
///
/// let addr = Ipv4::from_string("192.168.1.100").unwrap();
/// let netmask = Ipv4::from_string("255.255.255.0").unwrap();
/// let gateway = Ipv4::from_string("192.168.1.1").unwrap();
/// let outside_gateway = Ipv4::from_string("10.0.0.0").unwrap();
///
/// let eth0 = Device::new("eth0", None);
/// eth0.ipv4_link_add(addr, netmask).unwrap();
/// let link = Ipv4Link::get(addr).unwrap();
///
/// // Cannot add a route using a gateway with not route to it
/// assert_eq!(route_add(addr, netmask, Some(outside_gateway), 10, None), Err(PicoError::HostIsUnreachable));
///
/// // Add a route for the network
/// route_add(addr, netmask, None, 10, Some(link)).unwrap();
/// ```
pub fn route_add(address: Ipv4, netmask: Ipv4, gateway: Option<Ipv4>, metric: i32, link: Option<Ipv4Link>) -> Result<(), PicoError> {
    if gateway.is_none() && link.is_none() {
        return Err(PicoError::InvalidArgument);
    }

    let gateway = gateway.unwrap_or(Ipv4(0));
    let link: *mut pico_ipv4_link = link.map(|l| l.into()).unwrap_or(ptr::null_mut());

    match get_res(unsafe { pico_ipv4_route_add(address.into(), netmask.into(), gateway.into(), metric, link) }) {
        Ok(_) => Ok(()),
        Err(e @ PicoError::NotEnoughMemory) |
        Err(e @ PicoError::HostIsUnreachable) |
        Err(e @ PicoError::NetworkUnreachable) => Err(e),
        Err(res) => panic!(format!("Unexpected error from pico_ipv4_route_add: {:?}", res)),
    }
}

/// `pico_ipv4_route_add` for default routes
///
/// See also: `ipv4::route_add`
///
/// ```
/// # use rustotcp::ipv4::{route_add, default_route_add};
/// use rustotcp::{init, Ipv4, Ipv4Link, Device, PicoError};
///
/// init().unwrap();
///
/// let addr = Ipv4::from_string("192.168.1.100").unwrap();
/// let netmask = Ipv4::from_string("255.255.255.0").unwrap();
/// let gateway = Ipv4::from_string("192.168.1.1").unwrap();
/// let outside_gateway = Ipv4::from_string("10.0.0.0").unwrap();
///
/// let eth0 = Device::new("eth0", None);
/// eth0.ipv4_link_add(addr, netmask).unwrap();
/// let link = Ipv4Link::get(addr).unwrap();
///
/// // Add a route for the network
/// route_add(addr, netmask, None, 10, Some(link)).unwrap();
///
/// // Add a default route, via the gateway
/// default_route_add(Some(gateway), 10, Some(link)).unwrap();
/// ```
pub fn default_route_add(gateway: Option<Ipv4>, metric: i32, link: Option<Ipv4Link>) -> Result<(), PicoError> {
    if gateway.is_none() && link.is_none() {
        return Err(PicoError::InvalidArgument);
    }

    let zero_addr = pico_ip4 { addr: 0 };
    let gateway = gateway.unwrap_or(Ipv4(0));
    let link: *mut pico_ipv4_link = link.map(|l| l.into()).unwrap_or(ptr::null_mut());

    match get_res(unsafe { pico_ipv4_route_add(zero_addr, zero_addr, gateway.into(), metric, link) }) {
        Ok(_) => Ok(()),
        Err(e @ PicoError::NotEnoughMemory) |
        Err(e @ PicoError::HostIsUnreachable) |
        Err(e @ PicoError::NetworkUnreachable) => Err(e),
        Err(res) => panic!(format!("Unexpected error from pico_ipv4_route_add: {:?}", res)),
    }
}

/// `pico_ipv4_route_del`
///
/// ```
/// # use rustotcp::ipv4::{route_add, route_del};
/// use rustotcp::{init, Ipv4, Ipv4Link, Device, PicoError};
///
/// init().unwrap();
///
/// let addr = Ipv4::from_string("192.168.1.100").unwrap();
/// let netmask = Ipv4::from_string("255.255.255.0").unwrap();
/// let gateway = Ipv4::from_string("192.168.1.1").unwrap();
///
/// let eth0 = Device::new("eth0", None);
/// eth0.ipv4_link_add(addr, netmask).unwrap();
/// let link = Ipv4Link::get(addr).unwrap();
///
/// // Add a route for the network
/// route_add(addr, netmask, None, 10, Some(link)).unwrap();
///
/// // Delete it
/// route_del(addr, netmask, 10);
/// ```
pub fn route_del(address: Ipv4, netmask: Ipv4, metric: i32) {
    match get_res(unsafe { pico_ipv4_route_del(address.into(), netmask.into(), metric) }) {
        Ok(_) => {},
        Err(res) => panic!(format!("Unexpected error from pico_ipv4_route_del: {:?}", res)),
    }
}

/// `pico_ipv4_route_get_gateway`
///
/// ```
/// # use rustotcp::ipv4::{route_add, default_route_add, route_get_gateway};
/// use rustotcp::{init, Ipv4, Ipv4Link, Device, PicoError};
///
/// init().unwrap();
///
/// let addr = Ipv4::from_string("192.168.1.100").unwrap();
/// let other_addr = Ipv4::from_string("192.168.1.101").unwrap();
/// let outside_addr = Ipv4::from_string("10.10.10").unwrap();
/// let netmask = Ipv4::from_string("255.255.255.0").unwrap();
/// let gateway = Ipv4::from_string("192.168.1.1").unwrap();
///
/// let eth0 = Device::new("eth0", None);
/// eth0.ipv4_link_add(addr, netmask).unwrap();
/// let link = Ipv4Link::get(addr).unwrap();
///
/// // Add a route for the network
/// route_add(addr, netmask, Some(gateway), 10, Some(link)).unwrap();
///
/// assert_eq!(route_get_gateway(addr), Ok(None));
/// assert_eq!(route_get_gateway(other_addr), Ok(None));
/// assert_eq!(route_get_gateway(outside_addr), Err(PicoError::HostIsUnreachable));
///
/// // Add a default route, via the gateway
/// default_route_add(Some(gateway), 10, Some(link)).unwrap();
///
/// assert_eq!(route_get_gateway(outside_addr), Ok(Some(gateway)));
/// ```
pub fn route_get_gateway(address: Ipv4) -> Result<Option<Ipv4>, PicoError> {
    use picotcp_sys;
    unsafe { picotcp_sys::pico_err = picotcp_sys::pico_err_e::PICO_ERR_NOERR };
    let addr = &mut address.into();
    let gateway = unsafe { pico_ipv4_route_get_gateway(addr) }.addr;
    if gateway == 0 {
        match read_pico_err() {
            None => Ok(None), // No gateway needed
            Some(PicoError::HostIsUnreachable) => Err(PicoError::HostIsUnreachable),
            Some(res) => panic!(format!("Unexpected error from pico_ipv4_route_get_gateway: {:?}", res)),
        }
    }
    else {
        Ok(Some(Ipv4(gateway)))
    }
}
