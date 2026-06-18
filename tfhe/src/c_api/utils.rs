use std::os::raw::c_int;

pub fn catch_panic<F>(closure: F) -> c_int
where
    F: FnOnce(),
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)) {
        Ok(_) => 0,
        Err(err) => {
            super::error::replace_last_error_with_panic_payload(&err);
            1
        }
    }
}

pub(in crate::c_api) trait WrapperType: Sized {
    type Wrapped;

    fn wrap(wrapped: Self::Wrapped) -> Self;
    fn get(&self) -> &Self::Wrapped;
    fn get_mut(&mut self) -> &mut Self::Wrapped;
}

/// Implements [`WrapperType`] for a tuple-struct newtype: `pub struct W(I);`.
macro_rules! impl_wrapper_type {
    ($wrapper:ty, $wrapped:ty) => {
        impl $crate::c_api::utils::WrapperType for $wrapper {
            type Wrapped = $wrapped;

            fn wrap(wrapped: Self::Wrapped) -> Self {
                Self(wrapped)
            }

            fn get(&self) -> &Self::Wrapped {
                &self.0
            }

            fn get_mut(&mut self) -> &mut Self::Wrapped {
                &mut self.0
            }
        }
    };
}

pub(crate) use impl_wrapper_type;

/// Generic body of a C API `*_clone` function.
///
/// # Safety
///
/// `sself` must point to a valid `T`, and `result` must point to a writable `*mut T` slot.
pub(in crate::c_api) unsafe fn generic_c_api_clone<T>(sself: *const T, result: *mut *mut T) -> c_int
where
    T: WrapperType,
    T::Wrapped: Clone,
{
    catch_panic(|| {
        check_ptr_is_non_null_and_aligned(result).unwrap();

        *result = std::ptr::null_mut();
        let wrapper = get_ref_checked(sself).unwrap();
        let heap_allocated_object = Box::new(T::wrap(wrapper.get().clone()));

        *result = Box::into_raw(heap_allocated_object);
    })
}

/// Generic body of a C API `*_clone_from` function.
///
/// # Safety
///
/// `dest` and `src` must each point to a valid `T`. They may not alias.
pub(in crate::c_api) unsafe fn generic_c_api_clone_from<T>(dest: *mut T, src: *const T) -> c_int
where
    T: WrapperType,
    T::Wrapped: Clone,
{
    catch_panic(|| {
        let dest = get_mut_checked(dest).unwrap();
        let src = get_ref_checked(src).unwrap();

        dest.get_mut().clone_from(src.get());
    })
}

pub fn check_ptr_is_non_null_and_aligned<T>(ptr: *const T) -> Result<(), String> {
    if ptr.is_null() {
        return Err(format!("pointer is null, got: {ptr:p}"));
    }
    let expected_alignment = std::mem::align_of::<T>();
    if !(ptr as usize).is_multiple_of(expected_alignment) {
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
