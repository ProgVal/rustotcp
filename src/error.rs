use std::os::raw::c_int;
use std::ptr::read_volatile;

pub use picotcp_sys::pico_err_e;
use picotcp_sys::pico_err;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PicoError {
    OperationNotPermitted,
    FileNotFound,
    InterruptedFunctionCall,
    InputOutputError,
    NoSuchDeviceOrAddress,
    NotSuccessfulTryAgain,
    NotEnoughMemory,
    PermissionDenied,
    BadAddress,
    DeviceOrResourceBusy,
    FileAlreadyExists,
    InvalidArgument,
    NoNetwork,
    ProtocolError,
    ProtocolNotAvailable,
    ProtocolNotSupported,
    OperationNotSupportedOnSocket,
    AddressAlreadyInUse,
    AddressNotAvailable,
    NetworkIsDown,
    NetworkUnreachable,
    ConnectionReset,
    SocketIsConnected,
    SocketNotConnected,
    CannotReadTransportShutdown,
    ConnectionTimedOut,
    ConnectionRefused,
    HostIsDown,
    HostIsUnreachable,
}

impl PicoError {
    fn new(e: pico_err_e) -> Option<PicoError> {
        match e {
            pico_err_e::PICO_ERR_NOERR => None,
            pico_err_e::PICO_ERR_EPERM => Some(PicoError::OperationNotPermitted),
            pico_err_e::PICO_ERR_ENOENT => Some(PicoError::FileNotFound),
            pico_err_e::PICO_ERR_EINTR => Some(PicoError::InterruptedFunctionCall),
            pico_err_e::PICO_ERR_EIO => Some(PicoError::InputOutputError),
            pico_err_e::PICO_ERR_ENXIO => Some(PicoError::NoSuchDeviceOrAddress),
            pico_err_e::PICO_ERR_EAGAIN => Some(PicoError::NotSuccessfulTryAgain),
            pico_err_e::PICO_ERR_ENOMEM => Some(PicoError::NotEnoughMemory),
            pico_err_e::PICO_ERR_EACCESS => Some(PicoError::PermissionDenied),
            pico_err_e::PICO_ERR_EFAULT => Some(PicoError::BadAddress),
            pico_err_e::PICO_ERR_EBUSY => Some(PicoError::DeviceOrResourceBusy),
            pico_err_e::PICO_ERR_EEXIST => Some(PicoError::FileAlreadyExists),
            pico_err_e::PICO_ERR_EINVAL => Some(PicoError::InvalidArgument),
            pico_err_e::PICO_ERR_ENONET => Some(PicoError::NoNetwork),
            pico_err_e::PICO_ERR_EPROTO => Some(PicoError::ProtocolError),
            pico_err_e::PICO_ERR_ENOPROTOOPT => Some(PicoError::ProtocolNotAvailable),
            pico_err_e::PICO_ERR_EPROTONOSUPPORT => Some(PicoError::ProtocolNotSupported),
            pico_err_e::PICO_ERR_EOPNOTSUPP => Some(PicoError::OperationNotSupportedOnSocket),
            pico_err_e::PICO_ERR_EADDRINUSE => Some(PicoError::AddressAlreadyInUse),
            pico_err_e::PICO_ERR_EADDRNOTAVAIL => Some(PicoError::AddressNotAvailable),
            pico_err_e::PICO_ERR_ENETDOWN => Some(PicoError::NetworkIsDown),
            pico_err_e::PICO_ERR_ENETUNREACH => Some(PicoError::NetworkUnreachable),
            pico_err_e::PICO_ERR_ECONNRESET => Some(PicoError::ConnectionReset),
            pico_err_e::PICO_ERR_EISCONN => Some(PicoError::SocketIsConnected),
            pico_err_e::PICO_ERR_ENOTCONN => Some(PicoError::SocketNotConnected),
            pico_err_e::PICO_ERR_ESHUTDOWN => Some(PicoError::CannotReadTransportShutdown),
            pico_err_e::PICO_ERR_ETIMEDOUT => Some(PicoError::ConnectionTimedOut),
            pico_err_e::PICO_ERR_ECONNREFUSED => Some(PicoError::ConnectionRefused),
            pico_err_e::PICO_ERR_EHOSTDOWN => Some(PicoError::HostIsDown),
            pico_err_e::PICO_ERR_EHOSTUNREACH => Some(PicoError::HostIsUnreachable),
        }
    }
}


/// Returns the value of `pico_err_e::pico_err`, read safely and
/// converted to a `PicoError`.
pub fn read_pico_err() -> Option<PicoError> {
    PicoError::new(unsafe { read_volatile(&pico_err) }) // TODO: fix thread-safety
}

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `-1`, and `Ok(result)` otherwise.
pub fn get_res(res: c_int) -> Result<i32, PicoError> {
    if res == -1 {
        match read_pico_err() {
            Some(e) => Err(e),
            None => panic!("Unexpected PICO_ERR_NOERR after error return."),
        }
    }
    else {
        Ok(res as i32)
    }
}

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `NULL`, and `Ok(result)` otherwise.
pub fn get_res_ptr<T>(res: *mut T) -> Result<*mut T, PicoError> {
    if res.is_null() {
        match read_pico_err() {
            Some(e) => Err(e),
            None => panic!("Unexpected PICO_ERR_NOERR after error return."),
        }
    }
    else {
        Ok(res)
    }
}
