use std::os::raw::c_int;

pub use picotcp_sys::pico_err_e as PicoError;
use picotcp_sys::pico_err;

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `-1`, and `Ok(result)` otherwise.
pub fn get_res(res: c_int) -> Result<i32, PicoError> {
    if res == -1 {
        Err(unsafe { pico_err }) // TODO: fix thread-safety
    }
    else {
        Ok(res as i32)
    }
}
