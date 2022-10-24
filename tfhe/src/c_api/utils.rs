use std::fmt::{Debug, Display};
use std::os::raw::c_int;

pub fn catch_panic<F>(closure: F) -> c_int
where
    F: FnOnce(),
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)) {
        Ok(_) => 0,
        _ => 1,
    }
}

pub fn check_ptr_is_non_null_and_aligned<T>(ptr: *const T) -> Result<(), String> {
    if ptr.is_null() {
        return Err(format!("pointer is null, got: {:p}", ptr));
    }
    let expected_alignment = std::mem::align_of::<T>();
    if ptr as usize % expected_alignment != 0 {
        return Err(format!(
            "pointer is misaligned, expected {} bytes alignement, got pointer: {:p}. \
            You May have mixed some pointers in your function call. If that's not the case \
            check concrete-core-ffi.h for alignment constants for plain data types allocation.",
            expected_alignment, ptr
        ));
    }
    Ok(())
}

pub fn get_mut_checked<'a, T>(ptr: *mut T) -> Result<&'a mut T, String> {
    match check_ptr_is_non_null_and_aligned(ptr) {
        Ok(()) => unsafe {
            ptr.as_mut()
                .ok_or_else(|| "Error while converting to mut reference".into())
        },
        Err(e) => Err(e),
    }
}

pub fn get_ref_checked<'a, T>(ptr: *const T) -> Result<&'a T, String> {
    match check_ptr_is_non_null_and_aligned(ptr) {
        Ok(()) => unsafe {
            ptr.as_ref()
                .ok_or_else(|| "Error while converting to reference".into())
        },
        Err(e) => Err(e),
    }
}

pub fn engine_error_as_readable_string<R, T: Debug + Display>(error: T) -> Result<R, String> {
    Err(format!("{:#?}: {}", error, error))
}
