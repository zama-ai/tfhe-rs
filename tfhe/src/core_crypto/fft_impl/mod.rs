#![allow(deprecated)] // For the time being

pub use concrete_fft::c64;
use core::mem::MaybeUninit;

pub mod crypto;
pub mod math;

/// Convert a mutable slice reference to an uninitialized mutable slice reference.
///
/// # Safety
///
/// No uninitialized values must be written into the output slice by the time the borrow ends
#[inline]
pub unsafe fn as_mut_uninit<T>(slice: &mut [T]) -> &mut [MaybeUninit<T>] {
    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    // SAFETY: T and MaybeUninit<T> have the same layout
    core::slice::from_raw_parts_mut(ptr as *mut _, len)
}

/// Convert an uninitialized mutable slice reference to an initialized mutable slice reference.
///
/// # Safety
///
/// All the elements of the input slice must be initialized and in a valid state.
#[inline]
pub unsafe fn assume_init_mut<T>(slice: &mut [MaybeUninit<T>]) -> &mut [T] {
    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    // SAFETY: T and MaybeUninit<T> have the same layout
    core::slice::from_raw_parts_mut(ptr as *mut _, len)
}
