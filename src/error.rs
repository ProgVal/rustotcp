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
    fn new(e: pico_err_e) -> PicoError {
        match e {
            pico_err_e::PICO_ERR_NOERR => panic!("PicoError::new(pico_err_e::PICO_ERR_NOERR"),
            pico_err_e::PICO_ERR_EPERM => PicoError::OperationNotPermitted,
            pico_err_e::PICO_ERR_ENOENT => PicoError::FileNotFound,
            pico_err_e::PICO_ERR_EINTR => PicoError::InterruptedFunctionCall,
            pico_err_e::PICO_ERR_EIO => PicoError::InputOutputError,
            pico_err_e::PICO_ERR_ENXIO => PicoError::NoSuchDeviceOrAddress,
            pico_err_e::PICO_ERR_EAGAIN => PicoError::NotSuccessfulTryAgain,
            pico_err_e::PICO_ERR_ENOMEM => PicoError::NotEnoughMemory,
            pico_err_e::PICO_ERR_EACCESS => PicoError::PermissionDenied,
            pico_err_e::PICO_ERR_EFAULT => PicoError::BadAddress,
            pico_err_e::PICO_ERR_EBUSY => PicoError::DeviceOrResourceBusy,
            pico_err_e::PICO_ERR_EEXIST => PicoError::FileAlreadyExists,
            pico_err_e::PICO_ERR_EINVAL => PicoError::InvalidArgument,
            pico_err_e::PICO_ERR_ENONET => PicoError::NoNetwork,
            pico_err_e::PICO_ERR_EPROTO => PicoError::ProtocolError,
            pico_err_e::PICO_ERR_ENOPROTOOPT => PicoError::ProtocolNotAvailable,
            pico_err_e::PICO_ERR_EPROTONOSUPPORT => PicoError::ProtocolNotSupported,
            pico_err_e::PICO_ERR_EOPNOTSUPP => PicoError::OperationNotSupportedOnSocket,
            pico_err_e::PICO_ERR_EADDRINUSE => PicoError::AddressAlreadyInUse,
            pico_err_e::PICO_ERR_EADDRNOTAVAIL => PicoError::AddressNotAvailable,
            pico_err_e::PICO_ERR_ENETDOWN => PicoError::NetworkIsDown,
            pico_err_e::PICO_ERR_ENETUNREACH => PicoError::NetworkUnreachable,
            pico_err_e::PICO_ERR_ECONNRESET => PicoError::ConnectionReset,
            pico_err_e::PICO_ERR_EISCONN => PicoError::SocketIsConnected,
            pico_err_e::PICO_ERR_ENOTCONN => PicoError::SocketNotConnected,
            pico_err_e::PICO_ERR_ESHUTDOWN => PicoError::CannotReadTransportShutdown,
            pico_err_e::PICO_ERR_ETIMEDOUT => PicoError::ConnectionTimedOut,
            pico_err_e::PICO_ERR_ECONNREFUSED => PicoError::ConnectionRefused,
            pico_err_e::PICO_ERR_EHOSTDOWN => PicoError::HostIsDown,
            pico_err_e::PICO_ERR_EHOSTUNREACH => PicoError::HostIsUnreachable,
        }
    }
}

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `-1`, and `Ok(result)` otherwise.
pub fn get_res(res: c_int) -> Result<i32, PicoError> {
    if res == -1 {
        Err(unsafe { PicoError::new(read_volatile(&pico_err)) }) // TODO: fix thread-safety
    }
    else {
        Ok(res as i32)
    }
}

/// Takes the return of a pico function; return `Err(pico_err)` if it is
/// `NULL`, and `Ok(result)` otherwise.
pub fn get_res_ptr<T>(res: *mut T) -> Result<*mut T, PicoError> {
    if res.is_null() {
        Err(unsafe { PicoError::new(read_volatile(&pico_err)) }) // TODO: fix thread-safety
    }
    else {
        Ok(res)
    }
}
