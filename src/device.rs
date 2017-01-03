use std::ptr;
use std::ffi::CString;

use picotcp_sys::pico_device;
use picotcp_sys::pico_device_init;
use picotcp_sys::PICO_SIZE_ETH;

use error::get_res;

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
}
