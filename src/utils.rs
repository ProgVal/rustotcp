use std::os::raw::c_int;
use std::mem::transmute;

use picotcp_sys::pico_err_e;

pub fn cast_res(res: c_int) -> pico_err_e {
    unsafe { transmute::<c_int, pico_err_e>(res) }
}
