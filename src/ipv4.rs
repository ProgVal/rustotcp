use std::ffi::CString;

use picotcp_sys::pico_ipv4_to_string;
use picotcp_sys::pico_err_e;

use utils::cast_res;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, Ord, PartialOrd)]
pub struct Ipv4(u32);

impl Ipv4 {
    pub fn to_string(ip: Ipv4) -> Result<String, ()> {
        let ipbuf = CString::new("255.255.255.255").unwrap().into_raw();
        match cast_res(unsafe { pico_ipv4_to_string(ipbuf, ip.0) }) {
            pico_err_e::PICO_ERR_NOERR => {
                Ok(unsafe { CString::from_raw(ipbuf) }.into_string().unwrap())
            }
            pico_err_e::PICO_ERR_EINVAL => Err(()),
            res => panic!(format!("Unexpected return from pico_ipv4_to_string: {:?}", res)),
        }
    }
}
