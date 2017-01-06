use std::ptr;
use std::ffi::{CStr, CString};

use picotcp_sys::pico_device;
use picotcp_sys::pico_device_init;
use picotcp_sys::pico_ipv4_link_find;
use picotcp_sys::PICO_SIZE_ETH;

use error::{PicoError, get_res, get_res_ptr};
use ipv4::Ipv4;

#[derive(Debug)]
pub struct Device(*mut pico_device); // The pico_device is owned by the pico stack

impl<'dev> Into<*const pico_device> for &'dev Device {
    fn into(self) -> *const pico_device {
        self.0
    }
}

impl Device {
    /// Returns the name of the device.
    pub fn name(&self) -> String {
        let tmp = unsafe { (*self.0).name };
        (*unsafe { CStr::from_ptr(tmp.as_ptr()) }.to_string_lossy()).to_owned()
    }

    /// `pico_device_init` (not documented upstream)
    ///
    /// ```
    /// # use rustotcp::Device;
    /// rustotcp::init().unwrap();
    /// Device::new("eth0", None);
    /// Device::new("eth0", Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x54]));
    /// assert_eq!(Device::new("eth0", None).name(), "eth0");
    /// ```
    pub fn new(name: &str, mac: Option<[u8; PICO_SIZE_ETH as usize]>) -> Device {
        let raw = Box::into_raw(Box::new(pico_device::default()));
        let name_c = CString::new(name).unwrap();
        let res = match mac {
            Some(mut mac) =>
                unsafe { pico_device_init(raw, name_c.as_ptr(), mac.as_mut_ptr()) },
            None =>
                unsafe { pico_device_init(raw, name_c.as_ptr(), ptr::null_mut()) },
        };
        match get_res(res) {
            Ok(_) => Device(raw),
            Err(res) => panic!(format!("Unexpected error from pico_device_init: {:?}", res)),
        }
    }


    /// `pico_ipv4_link_find`
    ///
    /// TODO: return a reference
    ///
    /// Returns the `Device` corresponding to the given IPv4 address.
    ///
    /// ```
    /// # use rustotcp::Device;
    /// use rustotcp::{Ipv4, Ipv4Link};
    /// rustotcp::init().unwrap();
    /// let eth0 = Device::new("eth0", None);
    /// let tun0 = Device::new("tun0", None);
    /// let link1 = Ipv4Link::add(&eth0, Ipv4::from_string("192.168.1.1").unwrap(), Ipv4::from_string("255.255.255.0").unwrap()).unwrap();
    /// let link2 = Ipv4Link::add(&tun0, Ipv4::from_string("10.0.0.0").unwrap(), Ipv4::from_string("255.0.0.0").unwrap()).unwrap();
    /// assert_eq!(unsafe { Device::ipv4_link_find(Ipv4::from_string("192.168.1.1").unwrap()).map(|dev| dev.name()) }, Some("eth0".to_owned()));
    /// assert_eq!(unsafe { Device::ipv4_link_find(Ipv4::from_string("10.0.0.0").unwrap()).map(|dev| dev.name()) }, Some("tun0".to_owned()));
    /// assert_eq!(unsafe { Device::ipv4_link_find(Ipv4::from_string("127.0.0.1").unwrap()).map(|dev| dev.name()) }, None);
    /// ```
    pub unsafe fn ipv4_link_find(ip4: Ipv4) -> Option<Device> {
        match get_res_ptr(pico_ipv4_link_find(&mut ip4.into())) {
            Ok(dev) => Some(Device(dev)),
            Err(PicoError::NoSuchDeviceOrAddress) => None,
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_link_find: {:?}", res)),
        }
    }
}
