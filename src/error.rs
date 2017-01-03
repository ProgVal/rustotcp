use std::os::raw::c_int;
use std::ptr::read_volatile;

pub use picotcp_sys::pico_err_e;
use picotcp_sys::pico_err;

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `-1`, and `Ok(result)` otherwise.
pub fn get_res(res: c_int) -> Result<i32, pico_err_e> {
    if res == -1 {
        Err(unsafe { read_volatile(&pico_err) }) // TODO: fix thread-safety
    }
    else {
        Ok(res as i32)
    }
}

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `NULL`, and `Ok(result)` otherwise.
pub fn get_res_ptr<T>(res: *mut T) -> Result<*mut T, pico_err_e> {
    if res.is_null() {
        Err(unsafe { read_volatile(&pico_err) }) // TODO: fix thread-safety
    }
    else {
        Ok(res)
    }
}
