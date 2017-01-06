use picotcp_sys::pico_ipv4_link;
use picotcp_sys::pico_ipv4_link_add;
use picotcp_sys::pico_ipv4_link_get;
use picotcp_sys::pico_ipv4_link_del;
use picotcp_sys::pico_ipv4_nat_enable;
use picotcp_sys::pico_ipv4_nat_disable;
use picotcp_sys::pico_device;

use ipv4::Ipv4;
use device::Device;
use error::{PicoError, get_res};

#[derive(Debug)]
pub struct Ipv4Link<'dev> {
    ptr: *mut pico_ipv4_link,
    device: &'dev Device,
    ip4: Ipv4,
}

impl<'dev> Into<*mut pico_ipv4_link> for Ipv4Link<'dev> {
    fn into(self) -> *mut pico_ipv4_link {
        self.ptr
    }
}
impl<'a, 'dev> Into<*const pico_ipv4_link> for &'a Ipv4Link<'dev> {
    fn into(self) -> *const pico_ipv4_link {
        self.ptr
    }
}

impl<'dev> Ipv4Link<'dev> {
    /// `pico_ipv4_link_add`
    ///
    /// ```
    /// # use rustotcp::Ipv4Link;
    /// use rustotcp::{Device, Ipv4};
    /// rustotcp::init().unwrap();
    /// let eth0 = Device::new("eth0", None);
    /// assert!(Ipv4Link::add(&eth0, Ipv4::from_string("192.168.1.1").unwrap(), Ipv4::from_string("255.255.255.0").unwrap()).is_ok());
    /// ```
    pub fn add(device: &Device, ip4: Ipv4, netmask: Ipv4) -> Result<Ipv4Link, PicoError> {
        let device_ptr: *const pico_device = device.into();
        match get_res(unsafe { pico_ipv4_link_add(device_ptr as *mut _, ip4.into(), netmask.into()) }) { // TODO: do not cast *const to *mut

            Ok(_) => {
                let link_ptr = unsafe { pico_ipv4_link_get(&mut ip4.into()) };
                if link_ptr.is_null() {
                    panic!("pico_ipv4_link_get returned NULL for a link that was just added.".to_owned());
                }
                else {
                    let link = Ipv4Link { ptr: link_ptr, device: device, ip4: ip4 };
                    Ok(link)
                }
            },
            Err(e @ PicoError::NotEnoughMemory) |
            Err(e @ PicoError::NetworkUnreachable) |
            Err(e @ PicoError::HostIsUnreachable) => Err(e),
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_link_add: {:?}", res)),
        }
    }

    /// `pico_ipv4_link_del`
    ///
    /// ```
    /// # use rustotcp::Ipv4Link;
    /// use rustotcp::{Ipv4, Device};
    /// rustotcp::init().unwrap();
    /// let mut dev = Device::new("eth0", None);
    /// let link = Ipv4Link::add(&dev, Ipv4::from_string("192.168.1.1").unwrap(), Ipv4::from_string("255.255.255.0").unwrap()).unwrap();
    /// assert_eq!(link.del(), Ok(()));
    /// ```
    pub fn del(self) -> Result<(), PicoError> {
        let device_ptr: *const pico_device = self.device.into();
        match get_res(unsafe { pico_ipv4_link_del(device_ptr as *mut _, self.ip4.into()) }) { // TODO: do not cast *const to *mut
            Ok(_) => Ok(()),
            Err(PicoError::NoSuchDeviceOrAddress) =>
                panic!("pico_ipv4_link_get returned NoSuchDeviceOrAddress for a valid link object.".to_owned()),
            Err(res) => panic!(format!("Unexpected error from pico_ipv4_link_add: {:?}", res)),
        }
    }

    /// `pico_ipv4_nat_enable`
    ///
    /// TODO: add example/test
    pub fn nat_enable(&mut self) -> Result<(), PicoError> {
        get_res(unsafe { pico_ipv4_nat_enable(self.ptr) }).map(|_res| ())
    }

    /// `pico_ipv4_nat_disable`
    ///
    /// TODO: add example/test
    pub fn nat_disable() {
        unsafe { pico_ipv4_nat_disable() };
    }
}
