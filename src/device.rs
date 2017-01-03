use std::ptr;
use std::ffi::CString;

use picotcp_sys::pico_device;
use picotcp_sys::pico_device_init;
use picotcp_sys::pico_ipv4_link_add;
use picotcp_sys::pico_ipv4_link_del;
use picotcp_sys::PICO_SIZE_ETH;

use error::{PicoError, get_res};
use ipv4::Ipv4;

pub struct Device(pico_device);

impl Device {
    /// `pico_device_init` (not documented upstream)
    ///
    /// ```
    /// # use rustotcp::device::Device;
    /// rustotcp::init();
    /// Device::new("eth0", None);
    /// Device::new("eth0", Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    /// ```
    pub fn new(name: &str, mac: Option<[u8; PICO_SIZE_ETH as usize]>) -> Device {
        let mut raw = pico_device::default();
        let name_c = CString::new(name).unwrap();
        let res = match mac {
            Some(mut mac) =>
                unsafe { pico_device_init(&mut raw, name_c.as_ptr(), mac.as_mut_ptr()) },
            None =>
                unsafe { pico_device_init(&mut raw, name_c.as_ptr(), ptr::null_mut()) },
        };
        match get_res(res) {
            Ok(_) => Device(raw),
            Err(res) => panic!(format!("Unexpected error from pico_device_init: {:?}", res)),
        }
    }

    /// `pico_ipv4_link_add`
    ///
    /// ```
    /// # use rustotcp::device::Device;
    /// use rustotcp::ipv4::Ipv4;
    /// rustotcp::init();
    /// let mut dev = Device::new("eth0", None);
    /// assert_eq!(dev.ipv4_link_add(Ipv4::from_string("192.168.1.1").unwrap(), Ipv4::from_string("255.255.255.0").unwrap()), Ok(()));
    /// ```
    pub fn ipv4_link_add(&mut self, ip4: Ipv4, netmask: Ipv4) -> Result<(), PicoError> {
        match get_res(unsafe { pico_ipv4_link_add(&mut self.0 as *mut _, ip4.into(), netmask.into()) }) {
            Ok(_) => Ok(()),
            Err(e @ PicoError::NotEnoughMemory) |
            Err(e @ PicoError::NetworkUnreachable) |
            Err(e @ PicoError::HostIsUnreachable) => Err(e),
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_link_add: {:?}", res)),
        }
    }

    /// `pico_ipv4_link_del`
    ///
    /// ```
    /// # use rustotcp::device::Device;
    /// use rustotcp::ipv4::Ipv4;
    /// rustotcp::init();
    /// let mut dev = Device::new("eth0", None);
    /// dev.ipv4_link_add(Ipv4::from_string("192.168.1.1").unwrap(), Ipv4::from_string("255.255.255.0").unwrap()).unwrap();
    /// assert_eq!(dev.ipv4_link_del(Ipv4::from_string("192.168.1.1").unwrap()), Ok(()));
    /// ```
    ///
    /// ```
    /// # use rustotcp::device::Device;
    /// use rustotcp::error::PicoError;
    /// use rustotcp::ipv4::Ipv4;
    /// rustotcp::init();
    /// let mut dev = Device::new("eth0", None);
    /// dev.ipv4_link_add(Ipv4::from_string("192.168.1.1").unwrap(), Ipv4::from_string("255.255.255.0").unwrap()).unwrap();
    /// assert_eq!(dev.ipv4_link_del(Ipv4::from_string("192.168.2.1").unwrap()), Err(PicoError::NoSuchDeviceOrAddress));
    /// ```
    pub fn ipv4_link_del(&mut self, ip4: Ipv4) -> Result<(), PicoError> {
        match get_res(unsafe { pico_ipv4_link_del(&mut self.0 as *mut _, ip4.into()) }) {
            Ok(_) => Ok(()),
            Err(PicoError::NoSuchDeviceOrAddress) => Err(PicoError::NoSuchDeviceOrAddress),
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_link_add: {:?}", res)),
        }
    }
}
