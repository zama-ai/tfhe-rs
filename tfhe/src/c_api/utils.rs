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
        return Err(format!("pointer is null, got: {ptr:p}"));
    }
    let expected_alignment = std::mem::align_of::<T>();
    if ptr as usize % expected_alignment != 0 {
        return Err(format!(
            "pointer is misaligned, expected {expected_alignment} bytes alignment, got pointer: \
            {ptr:p}. You May have mixed some pointers in your function call. If that's not the \
            case check tfhe.h for alignment constants for plain data types allocation.",
        ));
    }
    Ok(())
}

/// Get a mutable reference from a pointer checking the pointer is well aligned for the given type.
///
/// # Safety
///
/// Caller of this function needs to make sure the pointer type corresponds to the data type being
/// pointed to.
///
/// Caller of this function needs to make sure the aliasing rules for mutable reference are
/// respected.
///
/// The basics are: at any time only a single mutable reference may exist to a given memory location
/// XOR any number of immutable reference may exist to a given memory location.
///
/// Failure to abide by the above rules will result in undefined behavior (UB).
pub(super) unsafe fn get_mut_checked<'a, T>(ptr: *mut T) -> Result<&'a mut T, String> {
    match check_ptr_is_non_null_and_aligned(ptr) {
        Ok(()) => ptr
            .as_mut()
            .ok_or_else(|| "Error while converting to mut reference".into()),
        Err(e) => Err(e),
    }
}

/// Get an immutable reference from a pointer checking the pointer is well aligned for the given
/// type.
///
/// # Safety
///
/// Caller of this function needs to make sure the pointer type corresponds to the data type being
/// pointed to.
///
/// Caller of this function needs to make sure the aliasing rules for immutable reference are
/// respected.
///
/// The basics are: at any time only a single mutable reference may exist to a given memory location
/// XOR any number of immutable reference may exist to a given memory location.
///
/// Failure to abide by the above rules will result in undefined behavior (UB).
pub(super) unsafe fn get_ref_checked<'a, T>(ptr: *const T) -> Result<&'a T, String> {
    match check_ptr_is_non_null_and_aligned(ptr) {
        Ok(()) => ptr
            .as_ref()
            .ok_or_else(|| "Error while converting to reference".into()),
        Err(e) => Err(e),
    }
}
