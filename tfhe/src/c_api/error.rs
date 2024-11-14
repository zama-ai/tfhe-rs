use std::any::Any;
use std::cell::RefCell;
use std::ffi::{c_char, CString};
use std::panic::AssertUnwindSafe;

enum LastError {
    None,
    Message(CString),
    // Only used when there was a memory panic happens
    // when trying to store the last panic message into the CString above
    NoMemory,
}

impl LastError {
    const NO_MEMORY_MSG: [c_char; 10] = [
        b'n' as c_char,
        b'o' as c_char,
        b' ' as c_char,
        b'm' as c_char,
        b'e' as c_char,
        b'm' as c_char,
        b'o' as c_char,
        b'r' as c_char,
        b'y' as c_char,
        b'\0' as c_char,
    ];

    const NO_ERROR_MSG: [c_char; 9] = [
        b'n' as c_char,
        b'o' as c_char,
        b' ' as c_char,
        b'e' as c_char,
        b'r' as c_char,
        b'r' as c_char,
        b'o' as c_char,
        b'r' as c_char,
        b'\0' as c_char,
    ];

    fn as_ptr(&self) -> *const c_char {
        match self {
            Self::None => Self::NO_ERROR_MSG.as_ptr(),
            Self::Message(cstring) => cstring.as_ptr(),
            Self::NoMemory => Self::NO_MEMORY_MSG.as_ptr(),
        }
    }

    /// Does not include the nul-byte
    fn len(&self) -> usize {
        match self {
            Self::None => Self::NO_ERROR_MSG.len() - 1,
            Self::Message(cstring) => cstring.as_bytes().len(),
            Self::NoMemory => Self::NO_MEMORY_MSG.len() - 1,
        }
    }
}

std::thread_local! {
   pub(in crate::c_api) static LAST_LOCAL_ERROR: RefCell<LastError> = const { RefCell::new(LastError::None) };
}

pub(in crate::c_api) fn replace_last_error_with_panic_payload(payload: &Box<dyn Any + Send>) {
    LAST_LOCAL_ERROR.with(|local_error| {
        let _previous_error = local_error.replace(panic_payload_to_error(payload));
    });
}

fn panic_payload_to_error(payload: &Box<dyn Any + Send>) -> LastError {
    // Add a catch panic as technically the to_vec could fail
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // Rust doc says:
        // An invocation of the panic!() macro in Rust 2021 or later
        // will always result in a panic payload of type &'static str or String.
        payload
            .downcast_ref::<&str>()
            .map_or_else(|| b"panic occurred".to_vec(), |s| s.as_bytes().to_vec())
    }));

    result.map_or_else(
        |_| LastError::NoMemory,
        |bytes| LastError::Message(CString::new(bytes).unwrap()),
    )
}

/// Returns a pointer to a nul-terminated string describing the last error in the thread.
///
/// * This pointer is only valid for as long as no other tfhe-rs function are called within this
///   thread.
///
/// This should be used to directly print/display or copy the error.
#[no_mangle]
pub unsafe extern "C" fn tfhe_error_get_last() -> *const c_char {
    LAST_LOCAL_ERROR.with_borrow(|last_error| last_error.as_ptr())
}

/// Returns the length of the current error message stored
///
/// The length **DOES NOT INCLUDE** the nul byte
#[no_mangle]
pub unsafe extern "C" fn tfhe_error_get_size() -> usize {
    LAST_LOCAL_ERROR.with_borrow(|last_error| last_error.len())
}

/// Clears the last error
#[no_mangle]
pub unsafe extern "C" fn tfhe_error_clear() {
    LAST_LOCAL_ERROR.replace(LastError::None);
}

/// Disables panic prints to stderr when a thread panics
#[no_mangle]
pub unsafe extern "C" fn tfhe_error_disable_automatic_prints() {
    std::panic::set_hook(Box::new(|_panic_info| {}));
}

/// Enables panic prints to stderr when a thread panics
#[no_mangle]
pub unsafe extern "C" fn tfhe_error_enable_automatic_prints() {
    // if the current hook is the default one, 'taking' it
    // will still make is registered
    let _ = std::panic::take_hook();
}
